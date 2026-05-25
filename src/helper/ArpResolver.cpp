#include <iostream>
#include "ArpResolver.hpp"
#include "NetworkHelper.hpp"
#include "ARP.hpp"
#include "Ethernet.hpp"
#include "CliHelper.hpp"

//* testing
#include "PacketHandler.hpp"
#include <chrono>

ArpResolver::ArpResolver(pcap_t* handle, const std::string& interface) : pcap_handle(handle), interface_name(interface)
{ }

void ArpResolver::build_arp_cache(const std::vector<uint32_t> &target_ips)
{
    MacAddress local_mac;
    uint32_t local_ip;

    if (!NetworkHelper::get_local_mac(interface_name, local_mac)) 
    {
        std::cerr << "Failed to get local MAC address." << std::endl;
        return;
    }

    if (!NetworkHelper::get_local_ip_pcap(interface_name, &local_ip)) 
    {
        std::cerr << "Failed to get local IP address." << std::endl;
        return;
    }

    for (const auto& target_ip : target_ips) 
    {
        send_arp_request(local_mac, local_ip, target_ip);
    }

    listen_arp_replies(3);

    std::vector<uint32_t> failed_ips;

    for (const auto& target_ip : target_ips)
    {
        if (!arp_mapper.has_ip(target_ip))
        {
            failed_ips.push_back(target_ip);
        }
    }

    // Print or handle failures
    if (!failed_ips.empty())
    {
        std::cout << "\nFailed ARP Resolutions:\n";
        for (const auto& ip : failed_ips)
        {
            // Assuming NetworkHelper has an ip_to_string function
            std::cout << CliHelper::ip_to_string(ip) << std::endl;
        }
        std::cout << std::endl;
    }

    arp_mapper.print_cache();
}

void ArpResolver::send_arp_request(const MacAddress& src_mac, const uint32_t& src_ip, 
                                    const uint32_t& dst_ip)
{
    std::vector<uint8_t> arp_request;
    ARP::build_arp(arp_request, &src_mac, &src_ip,
                    &ARP_BROADCAST_MAC, &dst_ip, ARP::Opcode::Request);
    
    Ethernet::build_ethernet(arp_request, src_mac, ARP_BROADCAST_MAC, 0x0806);

    
    if (pcap_sendpacket(pcap_handle, arp_request.data(), arp_request.size()) != 0) 
    {
        std::cerr << "Failed to send ARP request: " << pcap_geterr(pcap_handle) << std::endl;
    }
}

void ArpResolver::listen_arp_replies(int timeout_seconds)
{
    std::cout << "Listening for ARP replies..." << std::endl;

    struct pcap_pkthdr* header;
    const uint8_t* packet;
    
    auto start_time = std::chrono::steady_clock::now();
    auto timeout = std::chrono::seconds(timeout_seconds);

    while (std::chrono::steady_clock::now() - start_time < timeout) 
    {
        int result = pcap_next_ex(pcap_handle, &header, &packet);
        
        if (result == 0) //* no packet within timeout
            continue; 

        if (result < 0) 
        {
            std::cerr << "Packet read error or link dropped." << std::endl;
            break;
        }

        if (verify_arp_packet(packet, header->caplen))
        {
            const uint8_t* arp_payload = packet + ETHER_HDR_LEN; 
            const ARPHeader* arp = reinterpret_cast<const ARPHeader*>(arp_payload);
            uint32_t sender_ip = ntohl(arp->sender_ip);
        
            MacAddress sender_mac = arp->sender_mac;

            arp_mapper.update_cache(sender_ip, sender_mac); 
            
            /*std::printf("Host Discovered: %d.%d.%d.%d at %02x:%02x:%02x:%02x:%02x:%02x\n",
                        (sender_ip >> 24) & 0xFF, (sender_ip >> 16) & 0xFF,
                        (sender_ip >> 8) & 0xFF,  (sender_ip) & 0xFF,
                        sender_mac[0], sender_mac[1], sender_mac[2], 
                        sender_mac[3], sender_mac[4], sender_mac[5]);*/
        }

        
    }
}

bool ArpResolver::verify_arp_packet(const uint8_t* packet, const bpf_u_int32 length)
{
    if (length < ETHER_HDR_LEN + sizeof(ARPHeader))
    {
        return false;
    }

    uint16_t ether_type = ntohs(*reinterpret_cast<const uint16_t*>(&packet[12]));
    
    if (ether_type != 0x0806) //* Not an ARP packet, skip it
    {
        return false;
    }

    const uint8_t* arp_payload = packet + ETHER_HDR_LEN; 
    const ARPHeader* arp = reinterpret_cast<const ARPHeader*>(arp_payload);

    if (ntohs(arp->opcode)        == 2 &&       //* arp reply
        ntohs(arp->hardware_type) == 1 &&       //* ethernet
        ntohs(arp->protocol_type) == 0x0800)    //* IPv4
    {
        return true;
    }

    return false;
}
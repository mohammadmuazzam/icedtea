#pragma once
#include <map>
#include <vector>
#include <string>
#include "Types.hpp"

extern "C"
{
    #include "pcap.h"
}

//* Sends spoofed gratituos ARPs
class FriendlyArp
{
    private:
        pcap_t* pcap_handle;
        const std::map<uint32_t, MacAddress> arp_cache; //* real arp table
        MacAddress local_mac;
        MacAddress gateway_mac;
        uint32_t local_ip;
        uint32_t subnet_mask;

        bool send_arp_injection(const uint32_t& impersonate_src_ip, const MacAddress& target_mac, 
                                const uint32_t& target_ip);
    public:
        FriendlyArp(const std::map<uint32_t, MacAddress>& arp,
                    pcap_t* handle,
                    const NetworkContext& net_ctx);
        
        void send_arp_injections(std::vector<uint32_t> ip_addrs);
        void forward_packet(const struct pcap_pkthdr* header, const uint8_t* packet);
};
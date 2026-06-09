#pragma once
#include <string>
#include "ARP.hpp"

extern "C" 
{
    #include <pcap.h>
}

class NetworkHelper
{
    public:
        static bool get_local_mac(const std::string& interface_name, MacAddress& mac_out);
        static bool get_local_ip_pcap(const std::string& interface_name, uint32_t* ip_out);
        static uint32_t get_subnet_mask(const std::string& interface_name);
};
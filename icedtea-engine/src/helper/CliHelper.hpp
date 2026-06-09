#pragma once
#include <vector>
#include <string>
#include "Types.hpp"

extern "C" {
    #include <pcap.h>
}

namespace CliHelper
{
    char* option_get_interface(pcap_if_t *all_devs, char *error_buffer);

    std::vector<uint32_t> build_ip_list(const std::vector<std::string>& target_ips);

    std::string ip_to_string(uint32_t ip);

    std::string mac_to_string(const MacAddress& mac);
}

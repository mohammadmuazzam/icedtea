#include "CliHelper.hpp"
#include <iostream>


namespace CliHelper
{
    char *option_get_interface(pcap_if_t *all_devs, char *error_buffer)
    {
        short option = -1;
        if (all_devs == nullptr) {
            std::cerr << "No interfaces found: " << error_buffer << std::endl;
            return nullptr;
        }

        short i = 0;
        std::cout << "Available interfaces:" << std::endl;
        for (pcap_if_t *dev = all_devs; dev != nullptr; dev = dev->next) {
            std::cout << ++i << ") " << dev->name << std::endl;
        }

        while (option < 1 || option > i) 
        {
            std::cout << "Choose an interface: ";
            std::cin >> option;
            
            if (option < 1 || option > i) {
                std::cerr << "Invalid option. Please try again." << std::endl;
            }
        }

        for (pcap_if_t *dev = all_devs; dev != nullptr; dev = dev->next) 
        {
            if (--option == 0) {
                return dev->name;
            }
        }

        return nullptr;
    }
    //* index 0 is for gateway address
    std::vector<uint32_t> build_ip_list(const std::vector<std::string>& target_ips)
    {
        std::vector<uint32_t> target_ips_uint32;
        target_ips_uint32.reserve(target_ips.size());

        for (size_t i = 0; i < target_ips.size(); ++i)
        {
            uint32_t network_order_ip = 0;

            if (inet_pton(AF_INET, target_ips[i].c_str(), &network_order_ip) != 1)
            {
                if (i == Config::GATEWAY_INDEX)
                    std::cerr << "Invalid Gateway address: " << target_ips[i] << std::endl;
                else
                    std::cerr << "[ ERROR ] Skipping invalid IP address: " << target_ips[i] << std::endl;
                
                continue;
            }

            target_ips_uint32.push_back(ntohl(network_order_ip));
        }

        return target_ips_uint32;
    }

    std::string ip_to_string(uint32_t ip)
    {
        return std::to_string((ip >> 24) & 0xFF) + "." +
            std::to_string((ip >> 16) & 0xFF) + "." +
            std::to_string((ip >> 8)  & 0xFF) + "." +
            std::to_string(ip         & 0xFF);
    }

    std::string mac_to_string(const MacAddress& mac)
    {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
        return std::string(buf);
    }
}
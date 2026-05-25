#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <iomanip>
#include <unistd.h>
#include <cstring>
#include <iostream>

#include "NetworkHelper.hpp"

bool NetworkHelper::get_local_mac(const std::string& interface_name, MacAddress& mac_out) 
{
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) 
        return false;

    std::strncpy(ifr.ifr_name, interface_name.data(), IF_NAMESIZE - 1);
    
    //* requesting hardware (MAC) address
    if (ioctl(sock, SIOCGIFHWADDR, &ifr) < 0) 
    {
        close(sock);
        return false;
    }

    close(sock);
    
    std::memcpy(mac_out.data(), ifr.ifr_hwaddr.sa_data, 6);
    return true;
}

bool NetworkHelper::get_local_ip_pcap(const std::string& interface_name, uint32_t* ip_out) 
{
    pcap_if_t* all_devices;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&all_devices, errbuf) == -1) 
    {
        return false;
    }

    bool found = false;
    //* Loop through all network cards 
    for (pcap_if_t* device = all_devices; device != nullptr; device = device->next) 
    {
        if (std::string(device->name) == interface_name) 
        {
            // An interface can have multiple addresses, loop through them
            for (pcap_addr_t* address = device->addresses; address != nullptr; address = address->next) 
            {
                if (address->addr == nullptr) 
                    continue;

                //* if IPv4 address
                if (address->addr->sa_family == AF_INET) 
                {
                    struct sockaddr_in* sin = reinterpret_cast<struct sockaddr_in*>(address->addr);
                    uint32_t ip_addr = ntohl(sin->sin_addr.s_addr);

                    std::memcpy(ip_out, &ip_addr, 4);
                    found = true;
                    break;
                }
            }
        }

        if (found) 
            break;
    }

    pcap_freealldevs(all_devices);
    return found;
}


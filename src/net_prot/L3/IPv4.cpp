#include "IPv4.hpp"
#include <cstring>
#include <string>
#include <iostream>

extern "C" {
    #include <pcap.h>
}

IPv4::IPv4(const u_char* packet_data) : NetworkLayer(packet_data, -1)
{
    memcpy(&header, packet_data, sizeof(IPv4Header));
    payload = const_cast<u_char*>(packet_data + (header.version_ihl & 0x0F) * 4);
    set_size(ntohs(header.total_length));   //* total packet size (header + payload)
    type = Type::IPv4;
}

void IPv4::print() const
{
    std::cout << "\t[  IPv4 Header  ]" << std::endl;
    std::cout << "\tSource IPv4     : " << get_source_ip() << std::endl;
    std::cout << "\tDestination IPv4: " << get_destination_ip() << std::endl;
    std::cout << "\tProtocol      : " << (int)header.protocol << std::endl;
}

std::string IPv4::get_source_ip() const
{
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                header.source_ip[0], header.source_ip[1], 
                header.source_ip[2], header.source_ip[3]);
    return std::string(ip_str);
} 

std::string IPv4::get_destination_ip() const
{
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                header.destination_ip[0], header.destination_ip[1], 
                header.destination_ip[2], header.destination_ip[3]);
    return std::string(ip_str);
}

u_char IPv4::get_protocol() const
{
    return header.protocol;
}

u_char* IPv4::get_payload() const
{
    return payload;
}

u_int IPv4::get_payload_length() const
{
    return ntohs(header.total_length) - ((header.version_ihl & 0x0F) * 4);
}
#include "IPv4.hpp"
#include "CliHelper.hpp"
#include <cstring>
#include <string>
#include <iostream>

extern "C" {
    #include <pcap.h>
}

IPv4::IPv4(const uint8_t* packet_data) : NetworkLayer(packet_data, -1)
{
    memcpy(&header, packet_data, sizeof(IPv4Header));
    payload = const_cast<uint8_t*>(packet_data + (header.version_ihl & 0x0F) * 4);
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
    return CliHelper::ip_to_string(ntohl(header.source_ip));
} 

std::string IPv4::get_destination_ip() const
{
    return CliHelper::ip_to_string(ntohl(header.destination_ip));
}

uint32_t IPv4::get_src_ip_raw() const
{
    return header.source_ip;
}

uint32_t IPv4::get_dest_ip_raw() const
{
    return header.destination_ip;
}

uint8_t IPv4::get_protocol() const
{
    return header.protocol;
}

uint8_t* IPv4::get_payload() const
{
    return payload;
}

u_int IPv4::get_payload_length() const
{
    return ntohs(header.total_length) - ((header.version_ihl & 0x0F) * 4);
}
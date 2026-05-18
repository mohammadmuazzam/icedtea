#include <cstring>
#include <string>
#include <iostream>
#include "Ethernet.hpp"

extern "C" {
    #include <pcap.h>
}

Ethernet::Ethernet(const u_char* packet_data, bpf_u_int32 length) : DataLinkLayer(packet_data, length)
{
    memcpy(header.destination, packet_data, ETHER_ADDR_LEN);
    memcpy(header.source, packet_data + ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    header.type = ntohs(*(u_short*)(packet_data + 2*ETHER_ADDR_LEN));
    payload = const_cast<u_char*>(packet_data + ETHER_HDR_LEN);
    type = Type::Ethernet;
}

void Ethernet::print() const
{
    std::cout << "[  Ethernet Header  ]" << std::endl;
    std::cout << "Source MAC     : " << get_source_mac() << std::endl;
    std::cout << "Destination MAC: " << get_destination_mac() << std::endl;
    std::cout << "EtherType      : 0x" << std::hex << get_ethertype() << std::dec << std::endl;
}

std::string Ethernet::get_source_mac() const
{
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                header.source[0], header.source[1], header.source[2],
                header.source[3], header.source[4], header.source[5]);
    return std::string(mac_str);
} 

std::string Ethernet::get_destination_mac() const
{
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                header.destination[0], header.destination[1], header.destination[2],
                header.destination[3], header.destination[4], header.destination[5]);
    return std::string(mac_str);
}

u_short Ethernet::get_ethertype() const
{
    return header.type;
}

u_char* Ethernet::get_payload() const
{
    return payload;
}


#include <cstring>
#include <string>
#include <iostream>
#include "Ethernet.hpp"

void Ethernet::build_ethernet(std::vector<uint8_t>& buffer,
                              const MacAddress& src_mac, 
                              const MacAddress& dst_mac, 
                              uint16_t ether_type)
{
    size_t payload_index = buffer.size(); 

    //* move buffer to make space at the start for ethernet header
    buffer.resize(payload_index + ETHER_HDR_LEN);
    std::memmove(&buffer[ETHER_HDR_LEN], &buffer[0], payload_index);

    EthernetHeader* eth = reinterpret_cast<EthernetHeader*>(&buffer[0]);

    eth->source      = src_mac;
    eth->destination = dst_mac;
    eth->type        = htons(ether_type);
}

Ethernet::Ethernet(const uint8_t* packet_data, bpf_u_int32 length) : DataLinkLayer(packet_data, length)
{
    memcpy(header.destination.data(), packet_data, ETHER_ADDR_LEN);
    memcpy(header.source.data(), packet_data + ETHER_ADDR_LEN, ETHER_ADDR_LEN);
    header.type = ntohs(*(uint16_t*)(packet_data + 2*ETHER_ADDR_LEN));
    payload = const_cast<uint8_t*>(packet_data + ETHER_HDR_LEN);
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

uint16_t Ethernet::get_ethertype() const
{
    return header.type;
}

uint8_t* Ethernet::get_payload() const
{
    return payload;
}


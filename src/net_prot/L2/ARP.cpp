#include <iostream>
#include <arpa/inet.h>
#include "ARP.hpp"
#include "Ethernet.hpp"

#define IP_PROTOCOL_TYPE 0x0800
#define IP_PROTOCOL_SIZE 4

void ARP::build_arp(std::vector<uint8_t>& buffer,
                    const MacAddress *src_mac, const uint32_t *src_ip, 
                    const MacAddress *dst_mac, const uint32_t *dst_ip,
                    Opcode opcode)
{
    //* for what we've built before it (just in case)
    size_t start_idx = buffer.size();               
    buffer.resize(start_idx + sizeof(ARPHeader));

    ARPHeader* arp = reinterpret_cast<ARPHeader*>(&buffer[start_idx]);

    arp->sender_mac = *src_mac;
    arp->target_mac = *dst_mac;

    arp->hardware_type = htons(1);                  // Ethernet
    arp->protocol_type = htons(IP_PROTOCOL_TYPE);   // IPv4
    arp->hardware_size = ETHER_ADDR_LEN;            // MAC address length                   
    arp->protocol_size = IP_PROTOCOL_SIZE;
    arp->opcode        = htons(static_cast<uint16_t>(opcode));
    arp->sender_ip     = htonl(*src_ip);
    arp->target_ip     = htonl(*dst_ip);
}

ARP::ARP(const uint8_t* packet_data, u_int length) : DataLinkLayer(packet_data, length)
{
    memcpy(&header, packet_data, sizeof(ARPHeader));
    type = Type::ARP;
}

void ARP::print() const
{
    std::cout << "[  ARP Header  ]" << std::endl;

    if (get_opcode() == Opcode::Request) //* ARP Request
    {
        std::cout << "Who has " << get_target_ip() << "? Tell " << get_sender_ip() << " at " << get_sender_mac() << std::endl;
    }
    else if (get_opcode() == Opcode::Reply) //* ARP Reply
    {
        std::cout << get_sender_ip() << " is at " << get_sender_mac() << std::endl;
    }
    else
    {
        std::cout << "Unknown ARP opcode: " << static_cast<int>(get_opcode()) << std::endl;
    }
}

std::string ARP::get_sender_ip() const
{
    char ip_str[16];
    
    // Extract each byte sequentially from the 32-bit big-endian integer
    uint8_t b1 = (header.sender_ip >> 0)  & 0xFF;
    uint8_t b2 = (header.sender_ip >> 8)  & 0xFF;
    uint8_t b3 = (header.sender_ip >> 16) & 0xFF;
    uint8_t b4 = (header.sender_ip >> 24) & 0xFF;

    std::snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", b1, b2, b3, b4);
    return std::string(ip_str);
}

std::string ARP::get_target_ip() const
{
    char ip_str[16];
    
    // Extract each byte sequentially from the 32-bit big-endian integer
    uint8_t b1 = (header.target_ip >> 0)  & 0xFF;
    uint8_t b2 = (header.target_ip >> 8)  & 0xFF;
    uint8_t b3 = (header.target_ip >> 16) & 0xFF;
    uint8_t b4 = (header.target_ip >> 24) & 0xFF;

    std::snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", b1, b2, b3, b4);
    return std::string(ip_str);
}

std::string ARP::get_sender_mac() const
{
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                header.sender_mac[0], header.sender_mac[1], header.sender_mac[2],
                header.sender_mac[3], header.sender_mac[4], header.sender_mac[5]);
    return std::string(mac_str);
}

std::string ARP::get_target_mac() const
{
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                header.target_mac[0], header.target_mac[1], header.target_mac[2],
                header.target_mac[3], header.target_mac[4], header.target_mac[5]);
    return std::string(mac_str);
}

uint32_t ARP::get_sender_ip_raw() const
{
    return header.sender_ip;
}

void ARP::set_sender_ip(const std::string& ip_str)
{
    // inet_pton converts the string and writes directly to our 32-bit field
    if (inet_pton(AF_INET, ip_str.c_str(), &header.sender_ip) != 1)
    {
        header.sender_ip = ntohl(header.sender_ip);
        throw std::runtime_error("Invalid sender IPv4 address format: " + ip_str);
    }
}

void ARP::set_target_ip(const std::string& ip_str)
{
    if (inet_pton(AF_INET, ip_str.c_str(), &header.target_ip) != 1)
    {
        header.target_ip = ntohl(header.target_ip);
        throw std::runtime_error("Invalid target IPv4 address format: " + ip_str);
    }
}

void ARP::set_sender_mac(const std::string& mac_str)
{
    sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &header.sender_mac[0], &header.sender_mac[1], &header.sender_mac[2],
            &header.sender_mac[3], &header.sender_mac[4], &header.sender_mac[5]);
}

void ARP::set_target_mac(const std::string& mac_str)
{
    sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &header.target_mac[0], &header.target_mac[1], &header.target_mac[2],
            &header.target_mac[3], &header.target_mac[4], &header.target_mac[5]);
}

ARP::Opcode ARP::get_opcode() const
{
    return static_cast<ARP::Opcode>(ntohs(header.opcode));
}
#include <iostream>
#include "ARP.hpp"

ARP::ARP(const u_char* packet_data, u_int length) : DataLinkLayer(packet_data, length)
{
    memcpy(&header, packet_data, sizeof(ARPHeader));
    type = Type::ARP;
}

void ARP::print() const
{
    std::cout << "[  ARP Header  ]" << std::endl;
    std::cout << "Who has " << get_target_ip() << "? Tell " << get_sender_ip() << " at " << get_sender_mac() << std::endl;
}

std::string ARP::get_sender_ip() const
{
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                header.sender_ip[0], header.sender_ip[1], 
                header.sender_ip[2], header.sender_ip[3]);
    return std::string(ip_str);
}

std::string ARP::get_target_ip() const
{
    char ip_str[16];
    snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                header.target_ip[0], header.target_ip[1], 
                header.target_ip[2], header.target_ip[3]);
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

void ARP::set_sender_ip(const std::string& ip_str) const
{
    sscanf(ip_str.c_str(), "%hhu.%hhu.%hhu.%hhu", 
            &header.sender_ip[0], &header.sender_ip[1], 
            &header.sender_ip[2], &header.sender_ip[3]);
}

void ARP::set_target_ip(const std::string& ip_str) const
{
    sscanf(ip_str.c_str(), "%hhu.%hhu.%hhu.%hhu", 
            &header.target_ip[0], &header.target_ip[1], 
            &header.target_ip[2], &header.target_ip[3]);
}

void ARP::set_sender_mac(const std::string& mac_str) const
{
    sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &header.sender_mac[0], &header.sender_mac[1], &header.sender_mac[2],
            &header.sender_mac[3], &header.sender_mac[4], &header.sender_mac[5]);
}

void ARP::set_target_mac(const std::string& mac_str) const
{
    sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
            &header.target_mac[0], &header.target_mac[1], &header.target_mac[2],
            &header.target_mac[3], &header.target_mac[4], &header.target_mac[5]);
}
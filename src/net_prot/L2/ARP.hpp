#pragma once
#include <cstring>
#include <string>
#include "DataLinkLayer.hpp"

struct ARPHeader
{
    u_short hardware_type;          // Hardware type
    u_short protocol_type;          // Protocol type
    u_char hardware_size;           // Hardware address length
    u_char protocol_size;           // Protocol address length
    u_short opcode;                 // Operation code (request or reply)
    u_char sender_mac[6];           // Sender hardware address
    u_char sender_ip[4];            // Sender protocol address
    u_char target_mac[6];           // Target hardware address
    u_char target_ip[4];            // Target protocol address
};

class ARP : public DataLinkLayer
{
    private:
        ARPHeader header;
    public:
        ARP(const u_char* packet_data, u_int length);

        void print() const override;

        std::string get_sender_ip() const;
        std::string get_target_ip() const;
        std::string get_sender_mac() const;
        std::string get_target_mac() const;

        void set_sender_ip(const std::string& ip_str) const;
        void set_target_ip(const std::string& ip_str) const;
        void set_sender_mac(const std::string& mac_str) const;
        void set_target_mac(const std::string& mac_str) const;
};
#pragma once
#include <cstring>
#include <string>
#include <vector>
#include <array>
#include "DataLinkLayer.hpp"
#include "Types.hpp"

struct ARPHeader
{
    u_short hardware_type;          // Hardware type
    u_short protocol_type;          // Protocol type
    uint8_t hardware_size;           // Hardware address length
    uint8_t protocol_size;           // Protocol address length
    u_short opcode;                 // Operation code (request or reply)
    MacAddress sender_mac;           // Sender hardware address
    uint32_t sender_ip;            // Sender protocol address
    MacAddress target_mac;           // Target hardware address
    uint32_t target_ip;            // Target protocol address
}__attribute__((packed));

inline constexpr MacAddress ARP_BROADCAST_MAC = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

class ARP : public DataLinkLayer
{
    public:
        enum class Opcode
        {
            Request = 1,
            Reply = 2
        };

        static void build_arp(  std::vector<uint8_t>& buffer,
                                const MacAddress *src_mac, const uint32_t *src_ip, 
                                const MacAddress *dst_mac, const uint32_t *dst_ip,
                                Opcode opcode);

        ARP(const uint8_t* packet_data, u_int length);
        void print() const override;

        Opcode get_opcode() const;
        std::string get_sender_ip() const;
        std::string get_target_ip() const;
        std::string get_sender_mac() const;
        std::string get_target_mac() const;
        MacAddress get_sender_mac_raw() const;
        uint32_t get_sender_ip_raw() const;

        void set_sender_ip(const std::string& ip_str);
        void set_target_ip(const std::string& ip_str);
        void set_sender_mac(const std::string& mac_str);
        void set_target_mac(const std::string& mac_str);

    private:
        ARPHeader header;
};
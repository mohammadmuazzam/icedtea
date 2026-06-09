#pragma once
#include <cstring>
#include <string>
#include <iostream>
#include "NetworkLayer.hpp"

struct IPv4Header
{
    uint8_t version_ihl;             // Version (4 bits) + Internet header length (4 bits)
    uint8_t type_of_service;         // Type of service 
    u_short total_length;           // Total length 
    u_short id;                     // Identification
    u_short flags_fragment_offset;  // Flags (3 bits) + Fragment offset (13 bits)
    uint8_t time_to_live;            // Time to live
    uint8_t protocol;                // Protocol
    u_short header_checksum;        // Header checksum
    uint32_t source_ip;            // Source address
    uint32_t destination_ip;       // Destination address
};

class IPv4 : public NetworkLayer
{
    private:
        IPv4Header header;
        uint8_t* payload;
    public:
        IPv4(const uint8_t* packet_data);
        
        void print() const override;
        
        std::string get_source_ip() const;

        std::string get_destination_ip() const;

        uint32_t get_src_ip_raw() const;
        
        uint32_t get_dest_ip_raw() const;

        uint8_t get_protocol() const;

        uint8_t* get_payload() const;

        u_int get_payload_length() const;
};
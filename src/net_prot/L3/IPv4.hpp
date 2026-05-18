#pragma once
#include <cstring>
#include <string>
#include <iostream>
#include "NetworkLayer.hpp"

struct IPv4Header
{
    u_char version_ihl;             // Version (4 bits) + Internet header length (4 bits)
    u_char type_of_service;         // Type of service 
    u_short total_length;           // Total length 
    u_short id;                     // Identification
    u_short flags_fragment_offset;  // Flags (3 bits) + Fragment offset (13 bits)
    u_char time_to_live;            // Time to live
    u_char protocol;                // Protocol
    u_short header_checksum;        // Header checksum
    u_char source_ip[4];            // Source address
    u_char destination_ip[4];       // Destination address
};

class IPv4 : public NetworkLayer
{
    private:
        IPv4Header header;
        u_char* payload;
    public:
        IPv4(const u_char* packet_data);
        
        void print() const override;
        
        std::string get_source_ip() const;

        std::string get_destination_ip() const;

        u_char get_protocol() const;

        u_char* get_payload() const;

        u_int get_payload_length() const;
};
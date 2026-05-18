#pragma once
#include "DataLinkLayer.hpp"
#include <string>

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct EthernetHeader
{
    u_char destination[ETHER_ADDR_LEN];
    u_char source[ETHER_ADDR_LEN];
    u_short type;
};

class Ethernet : public DataLinkLayer
{
    private:
        EthernetHeader header;
        u_char* payload;
    public:
        Ethernet(const u_char* packet_data, bpf_u_int32 length);

        void print() const override;

        std::string get_source_mac() const;

        std::string get_destination_mac() const;

        u_short get_ethertype() const;

        u_char* get_payload() const;
};
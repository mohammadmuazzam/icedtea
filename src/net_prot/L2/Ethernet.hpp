#pragma once
#include <string>
#include <vector>
#include "DataLinkLayer.hpp"
#include "Types.hpp"

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct EthernetHeader
{
    MacAddress destination;
    MacAddress source;
    uint16_t type;
};

class Ethernet : public DataLinkLayer
{
    private:
        EthernetHeader header;
        uint8_t* payload;
    public:
        static void build_ethernet(std::vector<uint8_t>& buffer,
                              const MacAddress& src_mac, 
                              const MacAddress& dst_mac, 
                              uint16_t ether_type);

        Ethernet(const uint8_t* packet_data, bpf_u_int32 length);

        void print() const override;

        std::string get_source_mac() const;

        std::string get_destination_mac() const;

        uint16_t get_ethertype() const;

        uint8_t* get_payload() const;
};
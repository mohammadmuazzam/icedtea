#pragma once
#include <vector>
#include <string>
#include "ARP.hpp"

extern "C" {
    #include <pcap.h>
}

//* Rebuilds Ethernet header with new source and destination MAC addresses
class PacketBuilder
{
    public:
        PacketBuilder();
    private:
        //* change the source mac to THIS machine's mac
        void rebuild_ethernet_header(const uint8_t *src_mac, const uint8_t *dst_mac, char *packet);
};
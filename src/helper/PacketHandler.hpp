#pragma once
#include <memory>

#include "DataLinkLayer.hpp"
#include "NetworkLayer.hpp"
#include "TransportLayer.hpp"
#include "Ethernet.hpp"

extern "C" {
    #include <pcap.h>
}

class PacketHandler
{
    public:
        static int packet_count;
        Ethernet frame;
        std::unique_ptr<DataLinkLayer> data_link;
        std::unique_ptr<NetworkLayer> packet;
        std::unique_ptr<TransportLayer> segment;
        PacketHandler(const u_char *packet, u_int length);

    private:
    std::unique_ptr<DataLinkLayer> create_data_link(u_int length);
    std::unique_ptr<NetworkLayer> create_packet(u_int length);
    std::unique_ptr<TransportLayer> create_segment(u_int length);
};

void print_packet(u_char* packet_number, const struct pcap_pkthdr* header, const u_char* packet);
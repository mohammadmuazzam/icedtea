#include "PacketSniffer.hpp"
#include <iostream>
#include <string.h>
#include <functional>

PacketSniffer::PacketSniffer() :packet_count(0)
{ }

void PacketSniffer::start_sniffing(pcap_t *pcap_handle, 
                                    pcap_handler callback, 
                                    uint8_t *user_data,
                                    std::atomic<bool>& stop_flag,
                                    int max_packets)
{
    if (!pcap_handle)
    {
        std::cerr << "Interface not opened. Call open_interface() first." << std::endl;
        return;
    }
    if (!callback)
    {
        std::cerr << "No callback provided for packet handling." << std::endl;
        return;
    }
    //#pcap_loop(pcap_handle, max_packets, callback, (u_char *) user_data);

    struct pcap_pkthdr* header = nullptr;
    const uint8_t* packet_data = nullptr;
    int packet_count = 0;

    while (stop_flag.load()) 
    {
        if (max_packets > 0 && packet_count >= max_packets) break;

        int result = pcap_next_ex(pcap_handle, &header, &packet_data);
        if (result == 0) continue; 
        if (result < 0) break;

        callback((u_char*)user_data, header, packet_data);
        packet_count++;
    }
}


PacketSniffer::~PacketSniffer()
{
}
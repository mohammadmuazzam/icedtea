#include "PacketSniffer.hpp"
#include <iostream>
#include <string.h>
#include <functional>

PacketSniffer::PacketSniffer() :packet_count(0)
{ }

void PacketSniffer::start_sniffing(pcap_t *pcap_handle, 
                                    pcap_handler callback, 
                                    uint8_t *user_data,
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
    pcap_loop(pcap_handle, max_packets, callback, (u_char *) user_data);
}


PacketSniffer::~PacketSniffer()
{
}
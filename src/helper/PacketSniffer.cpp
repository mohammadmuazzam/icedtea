#include "PacketSniffer.hpp"
#include <iostream>
#include <string.h>
#include <functional>

PacketSniffer::PacketSniffer(std::string port_name) : interface_name(port_name), packet_count(0), pcap_handle(NULL) 
{ }

bool PacketSniffer::open_interface()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(interface_name.c_str(), PCAP_SNAPLEN, 1, 1000, error_buffer);
    if (pcap_handle == NULL)
    {
        std::cerr << "Error opening device: " << error_buffer << std::endl;
        return false;
    }
    return true;
}

void PacketSniffer::start_sniffing(pcap_handler callback, 
                                    u_char *user_data,
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
    std::cout << "Sniffing on: " << interface_name << "..." << std::endl;
    pcap_loop(pcap_handle, max_packets, callback, user_data);
}


PacketSniffer::~PacketSniffer()
{
    if (pcap_handle)
    {
        pcap_close(pcap_handle);
    }
}
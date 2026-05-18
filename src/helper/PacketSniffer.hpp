#pragma once
#include <iostream>
#include <string.h>
#include <functional>

extern "C" {
    #include <pcap.h>
}

#define PCAP_SNAPLEN 262144
#define NO_MAX_PACKETS -1

class PacketSniffer
{
    private:
        pcap_t *pcap_handle;
        std::string interface_name;
        int packet_count;
    
    public:
        PacketSniffer(std::string port_name);
        bool open_interface();

        void start_sniffing(pcap_handler callback = nullptr, 
                            u_char *user_data = nullptr,
                            int max_packets = NO_MAX_PACKETS);

        ~PacketSniffer();
};
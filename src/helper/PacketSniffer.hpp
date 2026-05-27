#pragma once
#include <iostream>
#include <string.h>
#include <functional>
#include <atomic>

extern "C" {
    #include <pcap.h>
}

#define NO_MAX_PACKETS -1

class PacketSniffer
{
    private:
        int packet_count;
    
    public:
        PacketSniffer();

        void start_sniffing(pcap_t *pcap_handle, 
                            pcap_handler callback, 
                            uint8_t *user_data,
                            std::atomic<bool>& stop_flag,
                            int max_packets = NO_MAX_PACKETS);

        ~PacketSniffer();
};
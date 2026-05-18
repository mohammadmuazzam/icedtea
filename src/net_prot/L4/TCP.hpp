#pragma once
#include <cstring>
#include "TransportLayer.hpp"

extern "C" {
    #include <pcap.h>
}

enum class TCPFlag
{
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
};

struct TCPHeader
{
    u_short source_port;            // Source port
    u_short destination_port;       // Destination port
    u_int sequence_number;          // Sequence number
    u_int acknowledgment_number;    // Acknowledgment number
    u_char data_offset_reserved;    // Data offset (4 bits) + Reserved (4 bits)
    u_char flags;                   // Flags
    u_short window_size;            // Window size
    u_short checksum;               // Checksum
    u_short urgent_pointer;         // Urgent pointer
};

class TCP : public TransportLayer
{
    private:
        TCPHeader header;
        u_char* payload;
    public:
        TCP(const u_char* packet_data, u_int segment_size);

        void print() const override;

        u_short get_source_port() const;

        u_short get_destination_port() const;

        u_int get_sequence_number() const;

        u_int get_acknowledgment_number() const;

        u_char get_flags() const;

        u_char* get_payload() const;

        u_int get_payload_length() const;
};


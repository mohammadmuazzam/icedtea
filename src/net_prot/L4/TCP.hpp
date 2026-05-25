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
    uint8_t data_offset_reserved;    // Data offset (4 bits) + Reserved (4 bits)
    uint8_t flags;                   // Flags
    u_short window_size;            // Window size
    u_short checksum;               // Checksum
    u_short urgent_pointer;         // Urgent pointer
};

class TCP : public TransportLayer
{
    private:
        TCPHeader header;
        uint8_t* payload;
    public:
        TCP(const uint8_t* packet_data, u_int segment_size);

        void print() const override;

        u_short get_source_port() const;

        u_short get_destination_port() const;

        u_int get_sequence_number() const;

        u_int get_acknowledgment_number() const;

        uint8_t get_flags() const;

        uint8_t* get_payload() const;

        u_int get_payload_length() const;
};


#include <cstring>
#include <string>
#include <iostream>

extern "C" {
    #include <pcap.h>
}

using namespace std;

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

class TCP
{
    private:
        TCPHeader header;
        u_char* payload;
    public:
        TCP(const u_char* packet_data)
        {
            memcpy(&header, packet_data, sizeof(TCPHeader));
            payload = const_cast<u_char*>(packet_data + ((header.data_offset_reserved >> 4) * 4));
        }

        void print() const
        {
            cout << "\t\t    [TCP Header]" << endl;
            cout << "\t\tSource Port      : " << get_source_port() << endl;
            cout << "\t\tDestination Port : " << get_destination_port() << endl;
            cout << "\t\tSequence Number  : " << get_sequence_number() << endl;
            cout << "\t\tAcknowledgment # : " << get_acknowledgment_number() << endl;
            cout << "\t\tFlags            : ";
            
            //! do better later
            if (header.flags & (char) TCPFlag::FIN) cout << "FIN ";
            if (header.flags & (char) TCPFlag::SYN) cout << "SYN ";
            if (header.flags & (char) TCPFlag::RST) cout << "RST ";
            if (header.flags & (char) TCPFlag::PSH) cout << "PSH ";
            if (header.flags & (char) TCPFlag::ACK) cout << "ACK ";
            if (header.flags & (char) TCPFlag::URG) cout << "URG ";
            cout << endl;
        }

        u_short get_source_port() const
        {
            return ntohs(header.source_port);
        } 

        u_short get_destination_port() const
        {
            return ntohs(header.destination_port);
        }

        u_int get_sequence_number() const
        {
            return ntohl(header.sequence_number);
        }

        u_int get_acknowledgment_number() const
        {
            return ntohl(header.acknowledgment_number);
        }

        u_char get_flags() const
        {
            return header.flags;
        }

        u_char* get_payload() const
        {
            return payload;
        }
};

enum class TCPFlag
{
    FIN = 0x01,
    SYN = 0x02,
    RST = 0x04,
    PSH = 0x08,
    ACK = 0x10,
    URG = 0x20,
};
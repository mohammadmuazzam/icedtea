#include <cstring>
#include <string>
#include <iostream>

extern "C" {
    #include <pcap.h>
}

using namespace std;

struct IPHeader
{
    u_char version_ihl;             // Version (4 bits) + Internet header length (4 bits)
    u_char type_of_service;         // Type of service 
    u_short total_length;           // Total length 
    u_short id;                     // Identification
    u_short flags_fragment_offset;  // Flags (3 bits) + Fragment offset (13 bits)
    u_char time_to_live;            // Time to live
    u_char protocol;                // Protocol
    u_short header_checksum;        // Header checksum
    u_char source_ip[4];            // Source address
    u_char destination_ip[4];       // Destination address
};

class IP
{
    private:
        IPHeader header;
        u_char* payload;
    public:
        IP(const u_char* packet_data)
        {
            memcpy(&header, packet_data, sizeof(IPHeader));
            payload = const_cast<u_char*>(packet_data + (header.version_ihl & 0x0F) * 4);
        }

        void print() const
        {
            cout << "\t  [IP Header]" << endl;
            cout << "\tSource IP     : " << get_source_ip() << endl;
            cout << "\tDestination IP: " << get_destination_ip() << endl;
            cout << "\tProtocol      : " << (int)header.protocol << endl;
        }

        string get_source_ip() const
        {
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                     header.source_ip[0], header.source_ip[1], 
                     header.source_ip[2], header.source_ip[3]);
            return string(ip_str);
        } 

        string get_destination_ip() const
        {
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                     header.destination_ip[0], header.destination_ip[1], 
                     header.destination_ip[2], header.destination_ip[3]);
            return string(ip_str);
        }

        u_char get_protocol() const
        {
            return header.protocol;
        }

        u_char* get_payload() const
        {
            return payload;
        }
};
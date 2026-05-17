#include <cstring>
#include <string>
#include "../helper/Out.cpp"

extern "C" {
    #include <pcap.h>
}

using namespace std;

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct EthernetHeader
{
    u_char destination[ETHER_ADDR_LEN];
    u_char source[ETHER_ADDR_LEN];
    u_short type;
};
class Ethernet
{
    private:
        EthernetHeader header;
        u_char* payload;
    public:
        Ethernet(const u_char* packet_data)
        {
            memcpy(header.destination, packet_data, ETHER_ADDR_LEN);
            memcpy(header.source, packet_data + ETHER_ADDR_LEN, ETHER_ADDR_LEN);
            header.type = ntohs(*(u_short*)(packet_data + 2*ETHER_ADDR_LEN));
            payload = const_cast<u_char*>(packet_data + ETHER_HDR_LEN);
        }

        void print() const
        {
            cout << "[Ethernet Header]" << endl;
            cout << "Source MAC     : " << get_source_mac() << endl;
            cout << "Destination MAC: " << get_destination_mac() << endl;
            cout << "EtherType      : 0x" << hex << get_ethertype() << dec << endl;
        }

        string get_source_mac() const
        {
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     header.source[0], header.source[1], header.source[2],
                     header.source[3], header.source[4], header.source[5]);
            return string(mac_str);
        } 

        string get_destination_mac() const
        {
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     header.destination[0], header.destination[1], header.destination[2],
                     header.destination[3], header.destination[4], header.destination[5]);
            return string(mac_str);
        }

        u_short get_ethertype() const
        {
            return header.type;
        }

        u_char* get_payload() const
        {
            return payload;
        }
};

#include <cstring>
#include <string>
#include <iostream>
#include "src/net_prot/Ethernet.cpp"
#include "src/net_prot/IP.cpp"
#include "src/net_prot/TCP.cpp"

extern "C" {
    #include <pcap.h>
}

using namespace std;

class PacketHandler
{
    private:
        Ethernet ethernet;



    public:
        static void handle_packet(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet)
        {
            cout << "Packet captured: " << header->len << " bytes" << endl;
            // You can add more detailed processing logic here
        }
};
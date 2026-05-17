#include <iostream>
#include <string.h>
#include <functional>

extern "C" {
    #include <pcap.h>
}

#define PCAP_SNAPLEN 262144
#define NO_MAX_PACKETS -1

using namespace std;

class PacketSniffer
{
    private:
        pcap_t *pcap_handle;
        string interface_name;
        int packet_count;
    
    public:
        PacketSniffer(string port_name) : interface_name(port_name), packet_count(0), pcap_handle(NULL) 
        {}

        bool open_interface()
        {
            char error_buffer[PCAP_ERRBUF_SIZE];
            pcap_handle = pcap_open_live(interface_name.c_str(), PCAP_SNAPLEN, 1, 1000, error_buffer);
            if (pcap_handle == NULL)
            {
                cerr << "Error opening device: " << error_buffer << endl;
                return false;
            }
            return true;
        }

        void start_sniffing(int max_packets = NO_MAX_PACKETS, 
                            pcap_handler callback = nullptr, 
                            u_char *user_data = nullptr)
        {
            if (!pcap_handle)
            {
                cerr << "Interface not opened. Call open_interface() first." << endl;
                return;
            }
            if (!callback)
            {
                cerr << "No callback provided for packet handling." << endl;
                return;
            }
            pcap_loop(pcap_handle, max_packets, callback, user_data);
        }


        ~PacketSniffer()
        {
            if (pcap_handle)
            {
                pcap_close(pcap_handle);
            }
        }

};
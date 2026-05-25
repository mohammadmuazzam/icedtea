#pragma once
#include <string>

#define PCAP_SNAPLEN 262144

extern "C" {
    #include <pcap.h>
}

class Interface
{
    public:
        Interface(std::string name);
        void open_interface();
        pcap_t* get_pcap_handle() const;
        std::string get_interface_name() const;
        
    private:
        pcap_t *pcap_handle;
        std::string interface_name;
};
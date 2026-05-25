#include <iostream>
#include "Interface.hpp"

Interface::Interface(std::string name) : interface_name(name), pcap_handle(NULL) 
{ }

void Interface::open_interface()
{
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_handle = pcap_open_live(interface_name.c_str(), PCAP_SNAPLEN, 1, 1000, error_buffer);
    
    if (pcap_handle == NULL)
    {
        std::cerr << "Error opening device: " << error_buffer << std::endl;
        throw std::runtime_error("Failed to open interface");
    }
}

pcap_t* Interface::get_pcap_handle() const
{
    return pcap_handle;
}

std::string Interface::get_interface_name() const
{
    return interface_name;
}
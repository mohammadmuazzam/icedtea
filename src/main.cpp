#include "PacketSniffer.hpp"
#include "PacketHandler.hpp"
#include "InterfaceSelector.hpp"
#include <iostream>


int main()
{
    char *device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devs;

    if (pcap_findalldevs(&all_devs, error_buffer) == -1 || all_devs == nullptr) {
        std::cerr << "Failed to find a valid interface." << std::endl;
        return 1;
    }

    device = option_get_interface(all_devs, error_buffer);

    if (device == NULL)
    {
        std::cerr << "Error finding device: " << error_buffer << std::endl;
        return 1;
    }

    PacketSniffer sniffer(device);
    
    sniffer.open_interface();
    sniffer.start_sniffing(print_packet, (u_char*)&PacketHandler::packet_count);
    pcap_freealldevs(all_devs);
}




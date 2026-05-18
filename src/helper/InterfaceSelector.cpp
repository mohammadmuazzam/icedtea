#include "InterfaceSelector.hpp"
#include <iostream>

char *option_get_interface(pcap_if_t *all_devs, char *error_buffer)
{
    short option = -1;
    if (all_devs == nullptr) {
        std::cerr << "No interfaces found: " << error_buffer << std::endl;
        return nullptr;
    }

    short i = 0;
    std::cout << "Available interfaces:" << std::endl;
    for (pcap_if_t *dev = all_devs; dev != nullptr; dev = dev->next) {
        std::cout << ++i << ") " << dev->name << std::endl;
    }

    while (option < 1 || option > i) 
    {
        std::cout << "Choose an interface: ";
        std::cin >> option;
        
        if (option < 1 || option > i) {
            std::cerr << "Invalid option. Please try again." << std::endl;
        }
    }

    for (pcap_if_t *dev = all_devs; dev != nullptr; dev = dev->next) 
    {
        if (--option == 0) {
            return dev->name;
        }
    }

    return nullptr;
}
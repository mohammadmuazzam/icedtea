#include <iostream>
#include "OSILayer.hpp"
#include "Out.hpp"

extern "C" {
    #include <pcap.h>
}

OSILayer::OSILayer(const u_char *data, u_int layer_size) : payload(data), size(layer_size)
{ }

void OSILayer::print() const
{
    std::cout << "[ Payload ]" << std::endl;      //! make it general
    Out::print_mem_split(payload, size);
    std::cout << std::endl;
}

const u_char* OSILayer::get_payload() const
{
    return payload;
}

u_int OSILayer::get_size() const
{
    return size;
}

void OSILayer::set_size(u_int new_size)
{
    size = new_size;
}
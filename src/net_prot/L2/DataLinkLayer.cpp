#include <iostream>

#include "DataLinkLayer.hpp"
#include "Out.hpp"

DataLinkLayer::DataLinkLayer(const u_char *data, u_int size) : OSILayer(data, size)
{ }

void DataLinkLayer::print() const
{
    std::cout << "[  Data Link Layer Payload  ]" << std::endl;  
    Out::print_mem_split(get_payload(), get_size());
    std::cout << std::endl;
}
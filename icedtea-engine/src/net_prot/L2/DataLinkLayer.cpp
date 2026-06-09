#include <iostream>

#include "DataLinkLayer.hpp"
#include "Out.hpp"

DataLinkLayer::DataLinkLayer(const uint8_t *data, u_int size) : OSILayer(data, size)
{ 
    type = Type::Generic;
}

void DataLinkLayer::print() const
{
    std::cout << "[  Data Link Layer Payload  ]" << std::endl;  
    Out::print_mem_split(get_payload(), get_size());
    std::cout << std::endl;
}
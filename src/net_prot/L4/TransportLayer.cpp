#include <iostream>
#include "TransportLayer.hpp"
#include "Out.hpp"

TransportLayer::TransportLayer(const uint8_t *data, u_int size) : OSILayer(data, size)
{ }

void TransportLayer::print() const
{
    std::cout << "\t\t[  Transport Layer Payload  ]" << std::endl;  
    Out::print_mem_split(get_payload(), get_size());
    std::cout << std::endl;
}
#include <iostream>

#include "NetworkLayer.hpp"
#include "Out.hpp"

NetworkLayer::NetworkLayer(const uint8_t *data, u_int size) : OSILayer(data, size)
{ }

void NetworkLayer::print() const
{
    std::cout << "\t[ Network Layer Payload ]" << std::endl;  
    Out::print_mem_split(get_payload(), get_size());
    std::cout << std::endl;
}
#include "OSILayer.hpp"
#pragma once

extern "C" {
    #include <pcap.h>
}

class DataLinkLayer : public OSILayer
{
    public:
        enum class Type
        {
            Ethernet,
            ARP,
            Generic
        };
        Type type;
        DataLinkLayer(const uint8_t *data, u_int size);
        virtual void print() const override;
};
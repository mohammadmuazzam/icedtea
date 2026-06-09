#include "OSILayer.hpp"
#pragma once
extern "C" {
    #include <pcap.h>
}

class TransportLayer : public OSILayer
{
    public:
        enum class Type 
        {
            TCP = 0x06,
            UDP = 0x11
        };
        Type type;

        TransportLayer(const uint8_t *data, u_int size);
        virtual void print() const override;
};
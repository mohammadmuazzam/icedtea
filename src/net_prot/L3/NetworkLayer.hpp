#include "OSILayer.hpp"
#pragma once
extern "C" {
    #include <pcap.h>
}

class NetworkLayer : public OSILayer
{
    public:
        enum class Type 
        {
            IPv4 = 0x0800,
            IPv6 = 0x86DD
        };
        Type type;

        NetworkLayer(const u_char *data, u_int size);
        virtual void print() const override;
};
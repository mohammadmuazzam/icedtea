#pragma once
#include <array>

extern "C" {
    #include <pcap.h>
}

using MacAddress = std::array<uint8_t, 6>; 
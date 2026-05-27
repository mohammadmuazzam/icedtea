#pragma once
#include <array>

extern "C" {
    #include <pcap.h>
}

using MacAddress = std::array<uint8_t, 6>;

struct Config {
    static constexpr int GATEWAY_INDEX = 0;
};

struct NetworkContext {
    MacAddress local_mac;
    MacAddress gateway_mac;
    uint32_t local_ip;
    uint32_t subnet_mask;
};

class FriendlyArp;
struct CaptureContext {
    FriendlyArp* arp_forwarder;
    pcap_dumper_t* pcap_dumper;
};
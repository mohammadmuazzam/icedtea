#include <map>
#include <string>
#include <array>
#include "PacketHandler.hpp"

extern "C"
{
    #include "pcap.h"
}


class ArpMapper
{
    private:
        //* IP address -> MAC address
        //* Format: X.X.X.X -> XX:XX:XX:XX:XX:XX
        std::map<uint32_t, MacAddress> arp_cache;
    public:
        ArpMapper();
        void print_cache() const;
        void update_cache(PacketHandler packet);
        void update_cache(const uint32_t &ip, const MacAddress &mac);
        void remove_entry(const uint32_t &ip);
        MacAddress get_mac(const uint32_t &ip);
        bool has_ip(const uint32_t& ip);
};
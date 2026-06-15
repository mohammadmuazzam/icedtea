#include <iostream>
#include "ArpMapper.hpp"
#include "ARP.hpp"
#include "CliHelper.hpp"

ArpMapper::ArpMapper()
{ }

void ArpMapper::print_cache() const
{
    std::cout << "--- ARP Cache ---" << std::endl;
    int i = 0;
    for (const auto& entry : arp_cache) 
    {
        std::cout << "[" << ++i << "] " << CliHelper::ip_to_string(entry.first) 
                                        << " \t->\t " << CliHelper::mac_to_string(entry.second) << std::endl;
    }
    std::cout << "-----------------" << std::endl;
    std::cout << std::endl;
}

void ArpMapper::update_cache(PacketHandler packet)
{
    if (packet.data_link && packet.data_link->type == DataLinkLayer::Type::ARP) 
    {
        ARP& arp = static_cast<ARP&>(*packet.data_link);
        if (arp.get_opcode() == ARP::Opcode::Reply)
        {
            uint32_t sender_ip = arp.get_sender_ip_raw();
            MacAddress sender_mac;
            std::memcpy(sender_mac.data(), arp.get_sender_mac().data(), 6);
            arp_cache[sender_ip] = sender_mac;
        }
    }
}

void ArpMapper::update_cache(const uint32_t &ip, const MacAddress &mac)
{
    arp_cache[ip] = mac;
}

MacAddress ArpMapper::get_mac(const uint32_t &ip)
{
    auto mac = arp_cache.find(ip);
    if (mac != arp_cache.end()) 
    {
        return mac->second;
    } 
    else 
    {
        return MacAddress{};
    }
}

void ArpMapper::remove_entry(const uint32_t &ip)
{
    arp_cache.erase(ip);
}

bool ArpMapper::has_ip(const uint32_t &ip)
{
    if (arp_cache.find(ip) == arp_cache.end())
    {
        return false;
    }

    return true;
}

//! inefficient but works for now
const std::map<uint32_t, MacAddress>& ArpMapper::get_arp_cache()
{
    return arp_cache;
}

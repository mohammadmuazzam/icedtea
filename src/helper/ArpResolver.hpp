#include <vector>
#include "ArpMapper.hpp"


extern "C"
{
    #include "pcap.h"
}


class ArpResolver
{
    public:
        ArpResolver(pcap_t* handle, const std::string& interface);
        void build_arp_cache(const std::vector<uint32_t> &target_ips);
        const std::map<uint32_t, MacAddress>& get_arp_cache();

    private:
        ArpMapper arp_mapper;
        pcap_t* pcap_handle;
        std::string interface_name;

        void send_arp_request(const MacAddress& src_mac, const uint32_t& src_ip, 
                            const uint32_t& dst_ip);
        void listen_arp_replies(int timeout_seconds);
        bool verify_arp_packet(const uint8_t* packet, const bpf_u_int32 length);
        

};
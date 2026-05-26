#include "PacketSniffer.hpp"
#include "PacketHandler.hpp"
#include "Interface.hpp"
#include "CliHelper.hpp"
#include "ArpResolver.hpp"
#include "FriendlyArp.hpp"
#include "NetworkHelper.hpp"
#include <iostream>
#include <vector>
#include <string>

#include <atomic>
#include <thread>

std::atomic<bool> running(true);
void arp_injection_worker(FriendlyArp& friendlyArp, const std::vector<uint32_t>& target_ips);

int main(int argc, char* argv[])
{
    if (argc < 2) 
    {
        std::cerr << "Usage: " << argv << " <IP_1> [IP_2] ... [IP_N]\n";
        std::cout << "IP address format: X.X.X.X\n";
        return 1; 
    }

    char* device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    std::vector<std::string> target_ips;
    pcap_if_t *all_devs;

    if (pcap_findalldevs(&all_devs, error_buffer) == -1 || all_devs == nullptr) {
        std::cerr << "Failed to find a valid interface." << std::endl;
        return 1;
    }

    device = CliHelper::option_get_interface(all_devs, error_buffer);

    if (device == NULL)
    {
        std::cerr << "Error finding device: " << error_buffer << std::endl;
        return 1;
    }
    
    Interface interface(device);

    try
    {
        interface.open_interface();
    }
    catch(const std::exception& e)
    {
        std::cerr << "[ ERROR ] " << e.what() << '\n';
    }
    

    for (int i = 1; i < argc; i++)
    {
        target_ips.push_back(argv[i]);
    }
    
    std::vector<uint32_t> target_ips_uint32 = CliHelper::build_ip_list(target_ips);
    
    ArpResolver arp_resolver(interface.get_pcap_handle(), interface.get_interface_name());
    arp_resolver.build_arp_cache(target_ips_uint32);

    MacAddress local_mac;
    uint32_t local_ip;

    if (!NetworkHelper::get_local_mac(interface.get_interface_name(), local_mac)) 
    {
        std::cerr << "Failed to get local MAC address." << std::endl;
        return -1;
    }

    if (!NetworkHelper::get_local_ip_pcap(interface.get_interface_name(), &local_ip)) 
    {
        std::cerr << "Failed to get local IP address." << std::endl;
        return -1;
    }

    FriendlyArp friendlyArp(arp_resolver.get_arp_cache(),
                            local_mac,
                            local_ip,
                            interface.get_pcap_handle());

    std::thread injection_thread(arp_injection_worker, std::ref(friendlyArp), std::ref(target_ips_uint32));
    PacketSniffer sniffer;
    sniffer.start_sniffing(interface.get_pcap_handle(), process_packet, nullptr);

    pcap_freealldevs(all_devs);
}

void arp_injection_worker(FriendlyArp& friendlyArp, const std::vector<uint32_t>& target_ips)
{
    while (running)
    {
        friendlyArp.send_arp_injections(target_ips);
        std::this_thread::sleep_for(std::chrono::seconds(10));
    }
}
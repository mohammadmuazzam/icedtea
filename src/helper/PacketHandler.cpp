#include <cstring>
#include <string>
#include <iostream>
#include "PacketHandler.hpp"
#include "ARP.hpp"
#include "IPv4.hpp"
#include "TCP.hpp"
#include "Out.hpp"

extern "C" {
    #include <pcap.h>
}

int PacketHandler::packet_count = 0;
const uint8_t* invalid_payload = (const uint8_t*) "X?X?X? Invalid/Empty Payload";
int invalid_payload_length = strlen((const char*)invalid_payload)-1;

PacketHandler::PacketHandler(const uint8_t *frm, u_int len) : frame(frm, len), packet(nullptr), segment(nullptr)
{
    data_link = create_data_link(len);
    packet = create_packet(len);
    segment = create_segment(len);
}

void print_packet(uint8_t* packet_number, const struct pcap_pkthdr* header, const uint8_t* packet)
{
    int count = (int) ++PacketHandler::packet_count;
    std::cout << "\n----- Packet captured (#" << count << "): " << header->len << " bytes -----" << std::endl;
    PacketHandler handler(packet, header->len);
    handler.frame.print();
    if (handler.data_link) 
    {
        handler.data_link->print();
    }
    handler.packet->print();

    if (handler.segment) 
    {
        handler.segment->print();
    }
}

//* create only ARP for now
std::unique_ptr<DataLinkLayer> PacketHandler::create_data_link(u_int length) 
{
    switch (frame.get_ethertype()) 
    {
        case 0x0806: //* ARP
            return std::make_unique<ARP>(frame.get_payload(), length);
        default:
            return nullptr;
    }
}

//* If the function returns NetworkLayer, we don't need to call create_segment()
std::unique_ptr<NetworkLayer> PacketHandler::create_packet(u_int length) 
{
    const uint8_t* payload = frame.get_payload();

    if (!payload) {
        std::cerr << "Warning: Invalid payload for Ethernet frame." << std::endl;
        return std::make_unique<NetworkLayer>(invalid_payload, invalid_payload_length);
    }

    switch (frame.get_ethertype()) {
        case 0x0800: // IPv4
            return std::make_unique<IPv4>(payload);
            
        default:
            return std::make_unique<NetworkLayer>(payload, length);
    }
}

std::unique_ptr<TransportLayer> PacketHandler::create_segment(u_int length) 
{
    if (packet->type == NetworkLayer::Type::IPv4) 
    {
        IPv4& ip = static_cast<IPv4&>(*packet);
        const uint8_t* payload = ip.get_payload();
        u_short payload_length = ip.get_payload_length();

        if (!payload || payload_length == 0) {
            std::cerr << "Warning: Invalid or empty payload for IPv4 packet. Length: " << payload_length << std::endl;
            return std::make_unique<TransportLayer>(invalid_payload, invalid_payload_length);
        }

        switch (ip.get_protocol()) {
            case IPPROTO_TCP:
                return std::make_unique<TCP>(payload, payload_length);
                
            default:
                return std::make_unique<TransportLayer>(payload, payload_length);
        }
    }
    else
    {
        return nullptr;
    }
}

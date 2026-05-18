#include "TCP.hpp"
#include "Out.hpp"
#include <cstring>
#include <string>
#include <iostream>

extern "C" {
    #include <pcap.h>
}

TCP::TCP(const u_char* packet_data, u_int segment_size) : TransportLayer(packet_data, segment_size)
{
    memcpy(&header, packet_data, sizeof(TCPHeader));
    payload = const_cast<u_char*>(packet_data + ((header.data_offset_reserved >> 4) * 4));
}

void TCP::print() const
{
    std::cout << "\t\t[  TCP Header  ]" << std::endl;
    std::cout << "\t\tSource Port      : " << get_source_port() << std::endl;
    std::cout << "\t\tDestination Port : " << get_destination_port() << std::endl;
    std::cout << "\t\tSequence Number  : " << get_sequence_number() << std::endl;
    std::cout << "\t\tAcknowledgment # : " << get_acknowledgment_number() << std::endl;
    std::cout << "\t\tFlags            : ";
    
    //! do better later
    if (header.flags & (char) TCPFlag::FIN) std::cout << "FIN ";
    if (header.flags & (char) TCPFlag::SYN) std::cout << "SYN ";
    if (header.flags & (char) TCPFlag::RST) std::cout << "RST ";
    if (header.flags & (char) TCPFlag::PSH) std::cout << "PSH ";
    if (header.flags & (char) TCPFlag::ACK) std::cout << "ACK ";
    if (header.flags & (char) TCPFlag::URG) std::cout << "URG ";

    std::cout << std::endl;
    Out::print_mem_split(payload, get_payload_length());
}

u_short TCP::get_source_port() const
{
    return ntohs(header.source_port);
} 

u_short TCP::get_destination_port() const
{
    return ntohs(header.destination_port);
}

u_int TCP::get_sequence_number() const
{
    return ntohl(header.sequence_number);
}

u_int TCP::get_acknowledgment_number() const
{
    return ntohl(header.acknowledgment_number);
}

u_char TCP::get_flags() const
{
    return header.flags;
}

u_char* TCP::get_payload() const
{
    return payload;
}

u_int TCP::get_payload_length() const
{
    return get_size() - ((header.data_offset_reserved >> 4) * 4);
}
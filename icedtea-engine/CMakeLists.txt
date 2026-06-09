cmake_minimum_required(VERSION 3.31)
project(PacketSniffer VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Tell the compiler where to look for header (.hpp) files
include_directories(src/helper src/net_prot src/net_prot/L4 src/net_prot/L3 src/net_prot/L2)

# List all your source (.cpp) files here
add_executable(icedtea 
    src/main.cpp

    src/helper/CliHelper.cpp
    src/helper/FriendlyArp.cpp
    src/helper/Out.cpp
    src/helper/Interface.cpp
    src/helper/NetworkHelper.cpp
    src/helper/PacketHandler.cpp
    src/helper/PacketSniffer.cpp
    src/helper/PacketBuilder.cpp
    src/helper/ArpMapper.cpp
    src/helper/ArpResolver.cpp
    
    src/net_prot/OSILayer.cpp
    src/net_prot/Types.hpp

    src/net_prot/L2/DataLinkLayer.cpp
    src/net_prot/L2/Ethernet.cpp
    src/net_prot/L2/ARP.cpp
    
    src/net_prot/L3/NetworkLayer.cpp
    src/net_prot/L3/IPv4.cpp
    
    src/net_prot/L4/TransportLayer.cpp
    src/net_prot/L4/TCP.cpp
)

set(CMAKE_BUILD_TYPE Debug)

# Link the libpcap library
target_link_libraries(icedtea pcap)
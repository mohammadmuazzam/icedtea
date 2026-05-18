#pragma once

extern "C" {
    #include <pcap.h>
}

char* option_get_interface(pcap_if_t *all_devs, char *error_buffer);
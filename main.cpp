#include "src/helper/Out.cpp"
#include "PacketSniffer.cpp"
#include "PacketHandler.cpp"



int main()
{
    char *device;
    device = pcap_lookupdev(NULL);
    if (device == NULL)
    {
        cerr << "Error finding device: " << pcap_geterr(NULL) << endl;
        return 1;
    }
}


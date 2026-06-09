#include "Out.hpp"
#include <iostream>
#include <iomanip>
#include <string.h>


// dumps raw memory in hex byte and printable split format
void Out::print_mem_split(const unsigned char *data_buffer, const unsigned int length) {
    unsigned char byte;
    unsigned int i, j;
    
    for(i=0; i < length; i++) 
    {
        byte = data_buffer[i];
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << " ";  // display byte in hex
        
        if (((i%16) == 15) || (i == length-1)) 
        {
            for (j = 0; j < 15-(i%16); j++)
                std::cout << "   ";
            
            std::cout << "| ";
            
            for (j = (i - (i%16)); j <= i; j++) 
            {  // display printable bytes from line
                byte = data_buffer[j];
                
                if ((31 < byte) && (byte < 127)) // outside printable char range
                    std::cout << byte;
                else
                    std::cout << ".";
            }
            std::cout << std::endl;
        }
        std::cout << std::dec;
    }
}
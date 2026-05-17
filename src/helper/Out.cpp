#include <iostream>
#include <string.h>

using namespace std;

class Out
{
    public:
        // dumps raw memory in hex byte and printable split format
        static void print_mem_split(const unsigned char *data_buffer, const unsigned int length) {
            unsigned char byte;
            unsigned int i, j;
            
            for(i=0; i < length; i++) 
            {
                byte = data_buffer[i];
                cout << hex << (int)byte << " ";  // display byte in hex
                
                if (((i%16) == 15) || (i == length-1)) 
                {
                    for (j = 0; j < 15-(i%16); j++)
                        cout << "   ";
                    
                    cout << "| ";
                    
                    for (j = (i - (i%16)); j <= i; j++) 
                    {  // display printable bytes from line
                        byte = data_buffer[j];
                        
                        if ((31 < byte) && (byte < 127)) // outside printable char range
                            cout << byte;
                        else
                            cout << ".";
                    }
                    cout << endl;
                }
            }
        }
};
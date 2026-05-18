#pragma once
extern "C" {
    #include <pcap.h>
}

class OSILayer
{
    public:
        OSILayer(const u_char *data, u_int size);
        virtual void print() const;
        const u_char* get_payload() const;
        u_int get_size() const;
        void set_size(u_int new_size); 
        
        virtual ~OSILayer() = default;

    private:
        const u_char *payload;
        u_int size;
};
#pragma once
extern "C" {
    #include <pcap.h>
}

class OSILayer
{
    public:
        OSILayer(const uint8_t *data, u_int size);
        virtual void print() const;
        const uint8_t* get_payload() const;
        u_int get_size() const;
        void set_size(u_int new_size); 
        
        virtual ~OSILayer() = default;

    private:
        const uint8_t *payload;
        u_int size;
};
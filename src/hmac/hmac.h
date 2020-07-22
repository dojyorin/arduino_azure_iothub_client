#ifndef hmac_Header
#define hmac_Header

#include "string.h"

class HMAC_SHA256{
public:
    HMAC_SHA256();
	~HMAC_SHA256();

    void generate(const uint8_t* key, const char* msg, uint8_t* output);

private:
    union{
        uint8_t b[64];
        uint32_t w[16];
    } buffer;

    union{
        uint32_t b[8];
        uint32_t w[8];
    } state;

    uint32_t byteCount;
    uint8_t bufferOffset;
    uint8_t keyBuffer[32];
    uint8_t innerHash[32];

    void add(uint8_t data);
    void init();
    uint32_t* result();
    void write(uint8_t data);
}

#endif
#include "hmac.h"

namespace{
    const uint32_t shaTable[64] = {
        0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
        0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
        0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
        0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
        0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
        0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
        0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
        0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
    };

    const uint32_t initialTable[8] = {
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    uint32_t ror32(uint32_t number, uint8_t bits){
        return (number << (32 - bits)) | (number >> bits);
    }
}

void HMAC_SHA256::add(uint8_t data){
    uint32_t t1 = 0;
    uint32_t t2 = 0;
    uint32_t a = this.state.w[0];
    uint32_t b = this.state.w[1];
    uint32_t c = this.state.w[2];
    uint32_t d = this.state.w[3];
    uint32_t e = this.state.w[4];
    uint32_t f = this.state.w[5];
    uint32_t g = this.state.w[6];
    uint32_t h = this.state.w[7];

    this.buffer.b[this.bufferOffset ^ 3] = data;
    this.bufferOffset++;

    if(this.bufferOffset == 64){
        for(uint8_t i = 0; i < 64; i++){
            if(i >= 16){
                t1 = this.buffer.w[i & 15] + this.buffer.w[(i - 7) & 15];
                t2 = this.buffer.w[(i - 2) & 15];
                t1 += ror32(t2, 17) ^ ror32(t2, 19) ^ (t2 >> 10);
                t2 = this.buffer.w[(i - 15) & 15];
                t1 += ror32(t2, 7) ^ ror32(t2, 18) ^ (t2 >> 3);
                this.buffer.w[i & 15] = t1;
            }

            t1 = h;
            t1 += ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25);
            t1 += g ^ (e & (g ^ f));
            t1 += shaTable[i];
            t1 += this.buffer.w[i & 15];
            t2 = ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22);
            t2 += ((b & c) | (a & (b | c)));
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        this.state.w[0] += a;
        this.state.w[1] += b;
        this.state.w[2] += c;
        this.state.w[3] += d;
        this.state.w[4] += e;
        this.state.w[5] += f;
        this.state.w[6] += g;
        this.state.w[7] += h;

        this.bufferOffset = 0;
    }
}

void HMAC_SHA256::init(){
    memcpy(this.state.b, initialTable, 32);
    this.byteCount = 0;
    this.bufferOffset = 0;
}

uint32_t* HMAC_SHA256::result(){
    this.add(0x80);

    while(this.bufferOffset != 56){
        this.add(0);
    }

    this.add(0);
    this.add(0);
    this.add(0);
    this.add(this.byteCount >> 29);
    this.add(this.byteCount >> 21);
    this.add(this.byteCount >> 13);
    this.add(this.byteCount >> 5);
    this.add(this.byteCount << 3);

    for(uint8_t i = 0; i < 8; i++){
        uint32_t a = this.state.w[i];
        uint32_t b = a << 24;
        b |= (a << 8) & 0x00FF0000;
        b |= (a >> 8) & 0x0000FF00;
        b |= a >> 24;
        this.state.w[i] = b;
    }

    return this.state.b;
}

void HMAC_SHA256::write(uint8_t data){
    ++this.byteCount;
    this.add(data);
}

void HMAC_SHA256::generate(const uint8_t* key, const char* msg, uint8_t* output){
    memcpy(this.keyBuffer, key, 32);

    this.init();

    for(uint8_t i = 0; i < 64; i++){
        this.write(this.keyBuffer[i] ^ 0x36);
    }

    while(*msg != '\0'){
        this.write(*msg++);
    }

    memcpy(this.innerHash, this.result(), 32);

    this.init();

    for(uint8_t i = 0; i < 64; i++){
        this.write(this.keyBuffer[i] ^ 0x5C);
    }

    for(uint8_t i = 0; i < 32; i++){
        this.write(this.innerHash[i]);
    }

    uint32_t* res = this.result();

    for(uint8_t i = 0; i < 64;){
        output[i++] = (char)(((*res & 0x000000F0) >> 4) + (((*res & 0x000000F0) >> 4) > 9 ? 0x57 : 0x30));
        output[i++] = (char)((*res & 0x0000000F) + ((*res & 0x0000000F) > 9 ? 0x57 : 0x30));
        output[i++] = (char)(((*res & 0x0000F000) >> 12) + (((*res & 0x0000F000) >> 12) > 9 ? 0x57 : 0x30));
        output[i++] = (char)(((*res & 0x00000F00) >> 8) + (((*res & 0x00000F00) >> 8) > 9 ? 0x57 : 0x30));
        output[i++] = (char)(((*res & 0x00F00000) >> 20) + (((*res & 0x00F00000) >> 20) > 9 ? 0x57 : 0x30));
        output[i++] = (char)(((*res & 0x000F0000) >> 16) + (((*res & 0x000F0000) >> 16) > 9 ? 0x57 : 0x30));
        output[i++] = (char)((*res >> 28) + ((*res >> 28) > 9 ? 0x57 : 0x30));
        output[i++] = (char)(((*res & 0x0F000000) >> 24) + (((*res & 0x0F000000) >> 24) > 9 ? 0x57 : 0x30));
        res++;
    }
}
#include "util_base64.h"

static const char* B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t b64_encode(const uint8_t* in, size_t inlen, char* out, size_t outcap, int string_out) {
    size_t opos=0;
    for (size_t i=0;i<inlen;i+=3) {
        if (opos+4 >= outcap) break;
        unsigned v=0; int take=0;
        for (int j=0;j<3;j++) {
            v = (v<<8) | ((i+j<inlen)? in[i+j] : 0);
            if (i+j<inlen) take++;
        }
        out[opos++] = B64[(v>>18)&0x3F];
        out[opos++] = B64[(v>>12)&0x3F];
        out[opos++] = (take>1)? B64[(v>>6)&0x3F] : '=';
        out[opos++] = (take>2)? B64[(v>>0)&0x3F] : '=';
    }
    if (string_out && opos<outcap) out[opos]=0;
    return opos;
}

static int b64_val(char c) {
    if (c>='A'&&c<='Z') return c-'A';
    if (c>='a'&&c<='z') return 26+(c-'a');
    if (c>='0'&&c<='9') return 52+(c-'0');
    if (c=='+') return 62;
    if (c=='/') return 63;
    if (c=='=') return 0;
    return -1;
}

size_t b64_decode(const char* in, uint8_t* out, size_t outcap) {
    size_t opos=0;
    for (size_t i=0; in[i]; ) {
        unsigned v=0; int count=0;
        for (int j=0;j<4 && in[i]; j++, i++) {
            if (in[i] == '=') {
                v = (v<<6);  // Shift for padding but don't increment count
                continue;
            }
            int x = b64_val(in[i]);
            if (x<0) continue;
            v = (v<<6) | (x & 0x3F);
            count++;
        }
        if (count==0) break;
        if (count>=2 && opos<outcap) out[opos++] = (v>>16)&0xFF;
        if (count>=3 && opos<outcap) out[opos++] = (v>>8)&0xFF;
        if (count>=4 && opos<outcap) out[opos++] = (v>>0)&0xFF;
    }
    return opos;
}

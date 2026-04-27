#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    bool got_init;
    bool have_cert;
    bool have_host_pub;
    bool established;
    char cert[800];       // device cert (base64 encoded PEM)
    char host_pub[129];   // 64 bytes * 2 hex + null = 129
    char mcu_pub[129];    // 64 bytes * 2 hex + null = 129
    uint32_t seed;        // Session key indicator (1 = key ready)
} session_t;

void session_init(session_t* s);
void session_zeroize(session_t* s);
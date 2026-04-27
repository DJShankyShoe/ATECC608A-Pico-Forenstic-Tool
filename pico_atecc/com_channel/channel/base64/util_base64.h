#pragma once
#include <stddef.h>
#include <stdint.h>

// Minimal base64 helpers (no streaming).
size_t b64_encode(const uint8_t* in, size_t inlen, char* out, size_t outcap, int string_out);
size_t b64_decode(const char* in, uint8_t* out, size_t outcap);

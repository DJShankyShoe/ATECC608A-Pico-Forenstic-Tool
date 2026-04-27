// aes_helpers.c
#include "aes_helpers.h"
#include <string.h>

size_t pkcs7_unpad(const uint8_t* data, size_t data_len) {
    if (data_len == 0) return 0;
    uint8_t padding_len = data[data_len - 1];
    if (padding_len > data_len || padding_len > 16) return data_len;
    for (size_t i = data_len - padding_len; i < data_len; i++) {
        if (data[i] != padding_len) return data_len;
    }
    return data_len - padding_len;
}

size_t pkcs7_pad(uint8_t* data, size_t data_len, size_t block_size) {
    size_t padding_len = block_size - (data_len % block_size);
    for (size_t i = 0; i < padding_len; i++) {
        data[data_len + i] = (uint8_t)padding_len;
    }
    return data_len + padding_len;
}
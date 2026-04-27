// aes_helpers.h
#ifndef AES_HELPERS_H
#define AES_HELPERS_H

#include <stdint.h>
#include <stddef.h>
#include "cryptoauthlib.h"

size_t pkcs7_unpad(const uint8_t* data, size_t data_len);
size_t pkcs7_pad(uint8_t* data, size_t data_len, size_t block_size);

#endif // AES_HELPERS_H
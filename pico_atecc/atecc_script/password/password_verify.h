#ifndef PASSWORD_VERIFY_H
#define PASSWORD_VERIFY_H

#include <stdint.h>
#include <stdbool.h>
#include "cryptoauthlib.h"

#ifdef __cplusplus
extern "C" {
#endif

// Configuration
#define PASSWORD_SLOT       13      // NoRead slot for encrypted password
#define HASH_SLOT           12      // Readable slot for password hash
#define IO_KEY_SLOT         4       // IO encryption key slot
#define PASSWORD_MAX_LEN    32      // Maximum password length

/**
 * Hash a password using ATECC608's hardware SHA-256
 * 
 * @param password Null-terminated input password string
 * @param hash Output buffer for 32-byte hash
 * @return ATCA_STATUS status code
 */
ATCA_STATUS password_hash(const char* password, uint8_t* hash);

/**
 * Store a password by hashing and saving the hash in a secure slot
 * 
 * @param password Null-terminated input password string
 * @return ATCA_STATUS status code
 */
ATCA_STATUS password_store(const char* password);

/**
 * Verify an input password against the stored hash
 * 
 * @param input Null-terminated input password string
 * @return true if password matches stored hash, false otherwise
 */
bool password_verify(const char* input);

#ifdef __cplusplus
}
#endif

#endif // PASSWORD_VERIFY_H
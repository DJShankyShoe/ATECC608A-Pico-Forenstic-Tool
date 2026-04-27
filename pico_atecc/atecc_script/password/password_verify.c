#include "password_verify.h"
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"

// Ensure NONCE_NUMIN_SIZE is defined
#ifndef NONCE_NUMIN_SIZE
#define NONCE_NUMIN_SIZE 20
#endif

// Provide password hashhing
ATCA_STATUS password_hash(const char* password, uint8_t* hash)
{
    if (!password || !hash) {
        return ATCA_BAD_PARAM;
    }
    
    size_t len = strlen(password);
    if (len == 0 || len > PASSWORD_MAX_LEN) {
        return ATCA_BAD_PARAM;
    }
    
    // Hash password using ATECC608's hardware SHA-256
    return atcab_sha(len, (const uint8_t*)password, hash);
}

// Store password hash in Slot 12
ATCA_STATUS password_store(const char* password)
{
    if (!password) {
        return ATCA_BAD_PARAM;
    }
    
    // Validate password length
    size_t len = strlen(password);
    if (len == 0 || len > PASSWORD_MAX_LEN) {
        printf("[password_store] Invalid password length: %zu (max: %d)\n", 
               len, PASSWORD_MAX_LEN);
        return ATCA_BAD_PARAM;
    }
    
    ATCA_STATUS status;
    
    // Step 1: Hash the password
    uint8_t password_hash_buf[32];
    status = password_hash(password, password_hash_buf);
    if (status != ATCA_SUCCESS) {
        printf("[password_store] Failed to hash password: 0x%08X\n", status);
        return status;
    }
    
    // Step 2: Store hash in Slot 12 (readable, for verification)
    status = atcab_write_zone(ATCA_ZONE_DATA, HASH_SLOT, 0, 0, 
                             password_hash_buf, 32);
    if (status != ATCA_SUCCESS) {
        printf("[password_store] Failed to write hash to Slot %d: 0x%08X\n", 
               HASH_SLOT, status);
        return status;
    }
    
    printf("[password_store] Password hash stored in Slot %d\n", HASH_SLOT);
    
    return ATCA_SUCCESS;
}

// Verify input password against stored hash in Slot 12
bool password_verify(const char* input) {
    if (!input) {
        return false;
    }
    
    size_t input_len = strlen(input);
    if (input_len == 0 || input_len > PASSWORD_MAX_LEN) {
        return false;
    }
    
    ATCA_STATUS status;
    
    // Step 1: Hash the input password
    uint8_t input_hash[32];
    status = password_hash(input, input_hash);
    if (status != ATCA_SUCCESS) {
        printf("[password_verify] Failed to hash input: 0x%08X\n", status);
        return false;
    }
    
    // Step 2: Read stored hash from Slot 12
    uint8_t stored_hash[32];
    status = atcab_read_zone(ATCA_ZONE_DATA, HASH_SLOT, 0, 0, stored_hash, 32);
    if (status != ATCA_SUCCESS) {
        printf("[password_verify] Failed to read hash from Slot %d: 0x%08X\n", 
               HASH_SLOT, status);
        return false;
    }
    
    // Step 3: Compare hashes using constant-time comparison
    return (memcmp(input_hash, stored_hash, 32) == 0);
}
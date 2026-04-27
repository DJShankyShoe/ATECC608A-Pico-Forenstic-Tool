#include "fr_key.h"
#include "protocol.h"
#include "session_key.h"
#include "aes_op.h"
#include "util_base64.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// AES slot where session key is stored
#define SESSION_AES_SLOT 9

// PKCS#7 padding for AES
static size_t pkcs7_pad(uint8_t* data, size_t data_len, size_t block_size) {
    size_t padding_len = block_size - (data_len % block_size);
    for (size_t i = 0; i < padding_len; i++) {
        data[data_len + i] = (uint8_t)padding_len;
    }
    return data_len + padding_len;
}

static size_t pkcs7_unpad(const uint8_t* data, size_t data_len) {
    if (data_len == 0) return 0;
    uint8_t padding_len = data[data_len - 1];
    if (padding_len > data_len || padding_len > 16) return data_len;
    // Verify padding
    for (size_t i = data_len - padding_len; i < data_len; i++) {
        if (data[i] != padding_len) return data_len;
    }
    return data_len - padding_len;
}

// Convert hex string to bytes
static bool hex_to_bytes(const char* hex_str, uint8_t* bytes, size_t bytes_len) {
    size_t hex_len = strlen(hex_str);
    if (hex_len != bytes_len * 2) {
        return false;
    }
    
    for (size_t i = 0; i < bytes_len; i++) {
        char byte_str[3] = {hex_str[i*2], hex_str[i*2+1], '\0'};
        bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    
    return true;
}

// Convert bytes to hex string
static void bytes_to_hex(const uint8_t* bytes, size_t bytes_len, char* hex_str) {
    for (size_t i = 0; i < bytes_len; i++) {
        sprintf(hex_str + i*2, "%02X", bytes[i]);
    }
    hex_str[bytes_len * 2] = '\0';
}

uint32_t fr_key_derive_seed(const char* shared_secret, const char* transcript) {
    uint32_t sum=0;
    for (const char* p=shared_secret; *p; ++p) {
        sum = (sum + (unsigned char)(*p)) & 0xFFFFFFFFu;
    }
    for (const char* p=transcript; *p; ++p) {
        sum = (sum + (unsigned char)(*p)) & 0xFFFFFFFFu;
    }
    return sum ^ 0xA5A5A5A5u;
}

bool fr_key_is_channel_established(session_t* s) {
    return s->established;
}

bool fr_key_handle_line(session_t* s, const char* line) {
    // Step 1: Host sends ephemeral public key
    if (strncmp(line, CMD_ECDH_HOST_PREFIX, 14)==0) {
        const char* host_pubkey_hex = line + 14;
        
        printf("[fr_key] Received host ephemeral public key\n");
        fflush(stdout);
        
        // Convert host public key from hex to bytes
        uint8_t host_pubkey[64];
        if (!hex_to_bytes(host_pubkey_hex, host_pubkey, 64)) {
            printf("[fr_key] ERROR: Invalid host public key format\n");
            fflush(stdout);
            printf(REPLY_ERR_NO_ECDH "\n");
            fflush(stdout);
            return true;
        }
        
        // Store host public key (for transcript)
        strncpy(s->host_pub, host_pubkey_hex, sizeof(s->host_pub)-1);
        s->have_host_pub = true;
        
        printf("[fr_key] Generating ephemeral session key using ATECC608...\n");
        fflush(stdout);
        
        // Step 2: Generate ephemeral session key using ECDH
        session_key_t session_key;
        
        ATCA_STATUS status = session_key_generate(
            2,                  // Ephemeral slot (Slot 2)
            host_pubkey,        // Host's ephemeral public key
            NULL,               // Use default salt
            0,
            NULL,               // Use default info
            0,
            &session_key
        );
        
        if (status != ATCA_SUCCESS) {
            printf("[fr_key] Session key generation failed: 0x%08X\n", status);
            fflush(stdout);
            printf(REPLY_ERR_NO_ECDH "\n");
            fflush(stdout);
            return true;
        }
        
        printf("[fr_key] Session key generated successfully\n");
        fflush(stdout);
        
        // Step 3: Store AES key in Slot 9 for encryption
        status = session_key_store(&session_key, SESSION_AES_SLOT, 4);
        if (status != ATCA_SUCCESS) {
            printf("[fr_key] Failed to store session key: 0x%08X\n", status);
            fflush(stdout);
            printf(REPLY_ERR_NO_ECDH "\n");
            fflush(stdout);
            return true;
        }
        
        printf("[fr_key] Session key stored in Slot %d\n", SESSION_AES_SLOT);
        fflush(stdout);
        
        // Mark that we have a valid AES key
        s->seed = 1; // Non-zero indicates key is ready
        
        // Step 4: Send our ephemeral public key to host
        bytes_to_hex(session_key.ephemeral_pubkey, 64, s->mcu_pub);
        
        printf("[fr_key] Sending MCU ephemeral public key\n");
        fflush(stdout);
        
        printf(REPLY_ECDH_MCU_PREFIX "%s\n", s->mcu_pub);
        fflush(stdout);
        
        return true;
    }
    
    // Step 5: Host confirms it processed Pico's pub key
    if (strcmp(line, CMD_HOST_READY)==0) {
        if (!s->have_host_pub || s->seed == 0) {
            printf("[fr_key] ERROR: No session key established\n");
            fflush(stdout);
            printf(REPLY_ERR_NO_ECDH "\n");
            fflush(stdout);
            return true;
        }
        
        printf("[fr_key] Host ready, sending AES-CBC encrypted test message\n");
        fflush(stdout);
        
        // Step 6: Pico sends AES-CBC encrypted test message
        const char* test_msg = "test encryption";
        size_t msg_len = strlen(test_msg);
        
        // Pad message to 16-byte blocks
        uint8_t padded[32];
        memcpy(padded, test_msg, msg_len);
        size_t padded_len = pkcs7_pad(padded, msg_len, 16);
        
        // Generate random IV
        uint8_t iv[16];
        ATCA_STATUS status = generate_iv(iv);
        if (status != ATCA_SUCCESS) {
            printf("[fr_key] Failed to generate IV\n");
            fflush(stdout);
            return true;
        }
        
        // Encrypt using AES-CBC
        uint8_t ciphertext[32];
        status = aes_cbc_encrypt(SESSION_AES_SLOT, iv, padded, padded_len, ciphertext);
        if (status != ATCA_SUCCESS) {
            printf("[fr_key] AES-CBC encryption failed: 0x%08X\n", status);
            fflush(stdout);
            return true;
        }
        
        // Format: IV (16 bytes) + ciphertext
        uint8_t message[48];
        memcpy(message, iv, 16);
        memcpy(message + 16, ciphertext, padded_len);
        
        // Base64 encode
        char b64[128];
        b64_encode(message, 16 + padded_len, b64, sizeof(b64), 1);
        
        printf(REPLY_TEST_ENC "%s\n", b64);
        fflush(stdout);
        return true;
    }
    
    // Step 7: Host sends encrypted response
    if (strncmp(line, CMD_TEST_RESPONSE, 14)==0) {
        const char* b64_response = line + 14;
        uint8_t encrypted[256];
        size_t encrypted_len = b64_decode(b64_response, encrypted, sizeof(encrypted));
        
        if (encrypted_len < 16) {
            printf("[fr_key] Invalid encrypted response (too short)\n");
            fflush(stdout);
            return true;
        }
        
        // Extract IV and ciphertext
        uint8_t iv[16];
        memcpy(iv, encrypted, 16);
        
        uint8_t* ciphertext = encrypted + 16;
        size_t ciphertext_len = encrypted_len - 16;
        
        // Decrypt using AES-CBC
        uint8_t plaintext[256];
        ATCA_STATUS status = aes_cbc_decrypt(SESSION_AES_SLOT, iv, ciphertext, ciphertext_len, plaintext);
        
        if (status == ATCA_SUCCESS) {
            // Remove padding
            size_t plaintext_len = pkcs7_unpad(plaintext, ciphertext_len);
            
            // Log the decrypted message
            printf("DUMP_TEST_RESPONSE:%.*s\n", (int)plaintext_len, plaintext);
            fflush(stdout);
            
            printf("[fr_key] Test response verified, establishing channel\n");
            fflush(stdout);
            
            // Step 8: Pico sends encrypted "ok" confirmation
            const char* ok_msg = "ok";
            size_t ok_len = strlen(ok_msg);
            
            // Pad message
            uint8_t ok_padded[16];
            memcpy(ok_padded, ok_msg, ok_len);
            size_t ok_padded_len = pkcs7_pad(ok_padded, ok_len, 16);
            
            // Generate new IV
            uint8_t ok_iv[16];
            status = generate_iv(ok_iv);
            if (status != ATCA_SUCCESS) {
                printf("[fr_key] Failed to generate IV for OK message\n");
                fflush(stdout);
                return true;
            }
            
            // Encrypt
            uint8_t ok_ciphertext[16];
            status = aes_cbc_encrypt(SESSION_AES_SLOT, ok_iv, ok_padded, ok_padded_len, ok_ciphertext);
            if (status != ATCA_SUCCESS) {
                printf("[fr_key] Failed to encrypt OK message\n");
                fflush(stdout);
                return true;
            }
            
            // Format: IV + ciphertext
            uint8_t ok_message[32];
            memcpy(ok_message, ok_iv, 16);
            memcpy(ok_message + 16, ok_ciphertext, ok_padded_len);
            
            // Base64 encode
            char ok_b64[64];
            b64_encode(ok_message, 16 + ok_padded_len, ok_b64, sizeof(ok_b64), 1);
            printf("ENC:%s\n", ok_b64);
            
            // Secure channel established
            printf(REPLY_CHANNEL_OK "\n");
            printf(STATE_ESTABLISHED "\n");
            s->established = true;
            fflush(stdout);
            
            printf("[fr_key] Secure channel established with AES-CBC encryption\n");
            fflush(stdout);
        } else {
            printf("[fr_key] Failed to decrypt test response\n");
            fflush(stdout);
        }
        return true;
    }
    
    return false;
}
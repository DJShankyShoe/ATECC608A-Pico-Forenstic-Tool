#include "fr_chan.h"
#include "protocol.h"
#include "aes_op.h"
#include "aes_helpers.h"
#include "util_base64.h"
#include "fr_data.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include "pico/stdlib.h"
#include "atecc.h"

#define SESSION_AES_SLOT 9

// Session tracking for telemetry storage
static uint32_t last_telem_seq = 0;

static int starts_with(const char* s, const char* p) {
    while (*p) {
        if (*s == 0) return 0;
        if (*s++ != *p++) return 0;
    }
    return 1;
}

bool fr_chan_handle_line(session_t* s, const char* line) {
    if (!line) return false;
    
    if (strncmp(line, CMD_ENC_PREFIX, 4) != 0) return false;
    
    if (!s || s->seed == 0) {
        printf("[fr_chan] No session key established\n");
        fflush(stdout);
        return true;
    }

    const char* b64 = line + 4;
    uint8_t encrypted[1024];
    size_t encrypted_len = b64_decode(b64, encrypted, sizeof(encrypted));

    printf("[fr_chan] DEBUG: encrypted_len = %zu\n", encrypted_len);
    fflush(stdout);
    
    if (encrypted_len < 16) {
        printf("[fr_chan] Invalid encrypted data (too short)\n");
        fflush(stdout);
        return true;
    }

    uint8_t iv[16];
    memcpy(iv, encrypted, 16);
    
    uint8_t* ciphertext = encrypted + 16;
    size_t ciphertext_len = encrypted_len - 16;
    
    uint8_t plaintext[1024];
    ATCA_STATUS status = aes_cbc_decrypt(SESSION_AES_SLOT, iv, ciphertext, ciphertext_len, plaintext);
    
    if (status != ATCA_SUCCESS) {
        printf("[fr_chan] AES-CBC decryption failed: 0x%08X\n", status);
        fflush(stdout);
        return true;
    }
    
    size_t plaintext_len = pkcs7_unpad(plaintext, ciphertext_len);
    
    if (plaintext_len >= sizeof(plaintext)) {
        plaintext_len = sizeof(plaintext) - 1;
    }
    plaintext[plaintext_len] = '\0';
    
    char* plain = (char*)plaintext;
    
    printf("[fr_chan] Decrypted: %.*s\n", (int)plaintext_len, plain);
    fflush(stdout);

    // Detect if this is telemetry data (starts with '{' for JSON or has TELEM_CHUNK prefix)
    bool is_telemetry = false;
    unsigned seq = 0;
    uint32_t stored_seq = 0;  // Preserve seq for later use
    const uint8_t* data_ptr = (const uint8_t*)plain;
    size_t data_len = plaintext_len;
    
    const char prefix[] = "TELEM_CHUNK:";
    if (starts_with(plain, prefix)) {
        // Explicit TELEM_CHUNK format
        is_telemetry = true;
        char* p = plain + sizeof(prefix) - 1;
        while (*p && isdigit((unsigned char)*p)) {
            seq = seq * 10 + (unsigned)(*p - '0');
            p++;
        }
        stored_seq = seq;  // Store immediately after parsing
        if (*p == ':') p++;
        
        // Data starts after prefix and sequence
        data_ptr = (const uint8_t*)p;
        data_len = plaintext_len - (p - plain);
        
        // Bounds check
        if (data_len > plaintext_len || data_len == 0) {
            printf("[fr_chan] ERROR: Invalid data_len calculation\n");
            fflush(stdout);
            return true;
        }
        
        printf("DUMP_TELEM_SEQ:%u:%.*s\n", stored_seq, (int)data_len, p);
        fflush(stdout);
    } else if (plaintext_len > 50 && plain[0] == '{') {
        // Auto-detect JSON telemetry data (no explicit prefix)
        is_telemetry = true;
        
        // Use incrementing sequence for auto-detected chunks
        static unsigned auto_seq = 0;
        seq = auto_seq++;
        stored_seq = seq;  // Store immediately
        
        // Data is the entire plaintext
        data_ptr = (const uint8_t*)plain;
        data_len = plaintext_len;
        
        printf("DUMP_TELEM_AUTO:%u:%.*s\n", stored_seq, (int)plaintext_len, plain);
        fflush(stdout);
    }
    
    // Store telemetry data to SD card with GCM encryption
    if (is_telemetry) {
        if (stored_seq == 0 || !fr_data_is_session_active() || (stored_seq != last_telem_seq + 1 && last_telem_seq != 0)) {
            // Start new session
            if (fr_data_is_session_active()) {
                fr_data_end_session();
            }
            
            // Generate unique random filename using ATECC608 RNG
            uint8_t random_bytes[4];
            status = generate_iv(random_bytes);  // Get 16 random bytes, use first 4
            
            char filename[64];
            if (status == ATCA_SUCCESS) {
                // Create filename with 8 hex characters: telem_A3F5B2C1.dat
                snprintf(filename, sizeof(filename), "telem_%02X%02X%02X%02X.dat",
                        random_bytes[0], random_bytes[1], random_bytes[2], random_bytes[3]);
            } else {
                // Fallback to timestamp-based if RNG fails
                uint32_t timestamp = (uint32_t)to_ms_since_boot(get_absolute_time());
                snprintf(filename, sizeof(filename), "telem_%08X.dat", timestamp);
            }
            
            int result = fr_data_start_session(filename);
            if (result != FR_DATA_OK) {
                printf("[fr_chan] ERROR: Failed to start data session\n");
                fflush(stdout);
            } else {
                printf("[fr_chan] Started telemetry session: %s\n", filename);
                fflush(stdout);
            }
        }
        
        // Store the telemetry data with GCM encryption
        if (fr_data_is_session_active()) {
            // Explicitly preserve seq to prevent corruption
            uint32_t chunk_seq = stored_seq;
            int result = fr_data_store_chunk(data_ptr, data_len, chunk_seq);
            if (result == FR_DATA_OK) {
                printf("[fr_chan] Chunk %u stored to SD card (encrypted with GCM)\n", chunk_seq);
                fflush(stdout);
            } else {
                printf("[fr_chan] ERROR: Failed to store chunk %u (error %d)\n", chunk_seq, result);
                fflush(stdout);
            }
        }
        
        last_telem_seq = stored_seq;
        
        // Use explicit variable for ACK
        uint32_t ack_seq = stored_seq;
        char ack_msg[64];
        snprintf(ack_msg, sizeof(ack_msg), "ACK_CHUNK:%u", ack_seq);
        
        uint8_t padded[80];
        size_t msg_len = strlen(ack_msg);
        memcpy(padded, ack_msg, msg_len);
        size_t padded_len = pkcs7_pad(padded, msg_len, 16);
        
        uint8_t ack_iv[16];
        status = generate_iv(ack_iv);
        if (status != ATCA_SUCCESS) {
            printf("[fr_chan] Failed to generate IV for ACK\n");
            fflush(stdout);
            printf("ACK_CHUNK:%u\n", ack_seq);
            fflush(stdout);
            return true;
        }
        
        uint8_t ack_ciphertext[80];
        status = aes_cbc_encrypt(SESSION_AES_SLOT, ack_iv, padded, padded_len, ack_ciphertext);
        if (status != ATCA_SUCCESS) {
            printf("[fr_chan] Failed to encrypt ACK\n");
            fflush(stdout);
            printf("ACK_CHUNK:%u\n", ack_seq);
            fflush(stdout);
            return true;
        }
        
        uint8_t ack_message[96];
        memcpy(ack_message, ack_iv, 16);
        memcpy(ack_message + 16, ack_ciphertext, padded_len);
        
        char ack_b64[256];
        b64_encode(ack_message, 16 + padded_len, ack_b64, sizeof(ack_b64), 1);
        printf("ENC:%s\n", ack_b64);
        fflush(stdout);
        
        printf("ACK_CHUNK:%u\n", ack_seq);
        fflush(stdout);
        
        return true;
    }

    printf("DUMP:%.*s\n", (int)plaintext_len, plain);
    fflush(stdout);

    const char* reply = "REPLY:OK from MCU";
    size_t reply_len = strlen(reply);
    
    uint8_t reply_padded[256];
    memcpy(reply_padded, reply, reply_len);
    size_t reply_padded_len = pkcs7_pad(reply_padded, reply_len, 16);
    
    uint8_t reply_iv[16];
    status = generate_iv(reply_iv);
    if (status != ATCA_SUCCESS) {
        printf("[fr_chan] Failed to generate IV for reply\n");
        fflush(stdout);
        return true;
    }
    
    uint8_t reply_ciphertext[256];
    status = aes_cbc_encrypt(SESSION_AES_SLOT, reply_iv, reply_padded, reply_padded_len, reply_ciphertext);
    if (status != ATCA_SUCCESS) {
        printf("[fr_chan] Failed to encrypt failed: 0x%08X\n", status);
        fflush(stdout);
        return true;
    }
    
    uint8_t reply_message[512];
    memcpy(reply_message, reply_iv, 16);
    memcpy(reply_message + 16, reply_ciphertext, reply_padded_len);
    
    char enc[1024];
    b64_encode(reply_message, 16 + reply_padded_len, enc, sizeof(enc), 1);
    printf("ENC:%s\n", enc);
    fflush(stdout);
    
    return true;
}
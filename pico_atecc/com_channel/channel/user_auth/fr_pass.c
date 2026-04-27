// fr_pass.c (updated with system kill)
#include "fr_pass.h"
#include "protocol.h"
#include "password_verify.h"
#include "aes_op.h"
#include "aes_helpers.h"
#include "util_base64.h"
#include "system_kill.h"
#include "pico/stdlib.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define SESSION_AES_SLOT 9
#define MAX_FAILED_ATTEMPTS 5
#define RETRY_DELAY_MS 3000

static char g_user_pw[64];
static int  g_user_auth_ok = 0;
static bool g_initialized = false;
static int  g_failed_attempts = 0;
static bool g_auth_complete = false;

void fr_pass_init(void) {
    g_user_pw[0] = 0;
    g_user_auth_ok = 0;
    g_failed_attempts = 0;
    g_initialized = true;
}

bool fr_pass_handle_line(session_t* s, const char* line) {
    // After authentication, stop intercepting ENC: messages
    if (g_auth_complete) {
        return false;
    }
    
    if (!g_initialized) {
        fr_pass_init();
    }

    if (strncmp(line, "ENC:", 4) == 0) {
        const char* b64_data = line + 4;
        uint8_t encrypted[256];
        size_t encrypted_len = b64_decode(b64_data, encrypted, sizeof(encrypted));

        printf("[fr_pass] DEBUG: encrypted_len = %zu\n", encrypted_len);
        fflush(stdout);
        
        if (encrypted_len < 16) {
            printf("[fr_pass] Invalid encrypted data (too short)\n");
            fflush(stdout);
            return false;
        }
        
        uint8_t iv[16];
        memcpy(iv, encrypted, 16);
        
        uint8_t* ciphertext = encrypted + 16;
        size_t ciphertext_len = encrypted_len - 16;
        
        uint8_t plaintext[256];
        ATCA_STATUS status = aes_cbc_decrypt(SESSION_AES_SLOT, iv, ciphertext, ciphertext_len, plaintext);
        
        if (status != ATCA_SUCCESS) {
            printf("[fr_pass] AES-CBC decryption failed: 0x%08X\n", status);
            fflush(stdout);
            return false;
        }
        
        size_t plaintext_len = pkcs7_unpad(plaintext, ciphertext_len);
        plaintext[plaintext_len] = '\0';
        
        char* decrypted_msg = (char*)plaintext;
        
        printf("[fr_pass] Decrypted message: %s\n", decrypted_msg);
        fflush(stdout);
        
        if (strncmp(decrypted_msg, CMD_USER_AUTH_PREFIX, 10) == 0) {
            const char* pw = decrypted_msg + 10;
            
            printf("[fr_pass] Attempting password verification...\n");
            fflush(stdout);
            
            if (password_verify(pw)) {
                g_failed_attempts = 0;
                strncpy(g_user_pw, pw, sizeof(g_user_pw)-1);
                g_user_auth_ok = 1;
                g_auth_complete = true; 
                
                printf("[fr_pass] ✅ Password verified successfully\n");
                fflush(stdout);
                
                const char* success_msg = "AUTH_SUCCESS";
                uint8_t padded[32];
                memcpy(padded, success_msg, strlen(success_msg));
                size_t padded_len = pkcs7_pad(padded, strlen(success_msg), 16);
                
                uint8_t response_iv[16];
                status = generate_iv(response_iv);
                if (status != ATCA_SUCCESS) {
                    printf("[fr_pass] Failed to generate IV\n");
                    fflush(stdout);
                    printf(REPLY_USER_AUTH_FAIL "\n");
                    fflush(stdout);
                    return true;
                }
                
                uint8_t response_ciphertext[32];
                status = aes_cbc_encrypt(SESSION_AES_SLOT, response_iv, padded, padded_len, response_ciphertext);
                if (status != ATCA_SUCCESS) {
                    printf("[fr_pass] Failed to encrypt response\n");
                    fflush(stdout);
                    printf(REPLY_USER_AUTH_FAIL "\n");
                    fflush(stdout);
                    return true;
                }
                
                uint8_t response_message[48];
                memcpy(response_message, response_iv, 16);
                memcpy(response_message + 16, response_ciphertext, padded_len);
                
                char response_b64[128];
                b64_encode(response_message, 16 + padded_len, response_b64, sizeof(response_b64), 1);
                printf("ENC:%s\n", response_b64);
                fflush(stdout);
                
                printf(REPLY_USER_AUTH_OK "\n");
                fflush(stdout);
                
            } else {
                g_user_pw[0] = 0;
                g_user_auth_ok = 0;
                g_failed_attempts++;
                
                printf("[fr_pass] ❌ Password verification failed (attempt %d/%d)\n", 
                       g_failed_attempts, MAX_FAILED_ATTEMPTS);
                fflush(stdout);
                
                if (g_failed_attempts >= MAX_FAILED_ATTEMPTS) {
                    printf("[fr_pass] 🔒 Max attempts reached - KILLING SYSTEM\n");
                    fflush(stdout);
                    
                    sleep_ms(500);
                    system_kill_session(s);
                    // Never returns
                }
                
                const char* fail_msg = "AUTH_FAILED";
                uint8_t padded[32];
                memcpy(padded, fail_msg, strlen(fail_msg));
                size_t padded_len = pkcs7_pad(padded, strlen(fail_msg), 16);
                
                uint8_t response_iv[16];
                status = generate_iv(response_iv);
                if (status == ATCA_SUCCESS) {
                    uint8_t response_ciphertext[32];
                    status = aes_cbc_encrypt(SESSION_AES_SLOT, response_iv, padded, padded_len, response_ciphertext);
                    if (status == ATCA_SUCCESS) {
                        uint8_t response_message[48];
                        memcpy(response_message, response_iv, 16);
                        memcpy(response_message + 16, response_ciphertext, padded_len);
                        
                        char response_b64[128];
                        b64_encode(response_message, 16 + padded_len, response_b64, sizeof(response_b64), 1);
                        printf("ENC:%s\n", response_b64);
                        fflush(stdout);
                    }
                }
                
                printf(REPLY_USER_AUTH_FAIL "\n");
                fflush(stdout);
                
                printf("[fr_pass] ⏱️  Rate limit delay: %d ms\n", RETRY_DELAY_MS);
                fflush(stdout);
                sleep_ms(RETRY_DELAY_MS);
            }
            
            return true;
        }
    }

    return false;
}

bool fr_pass_is_authenticated(void) {
    return g_user_auth_ok != 0;
}

const char* fr_pass_get_password(void) {
    return g_user_pw;
}

void fr_pass_clear(void) {
    memset(g_user_pw, 0, sizeof(g_user_pw));
    g_user_auth_ok = 0;
    g_failed_attempts = 0;
}
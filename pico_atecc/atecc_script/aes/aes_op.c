#include "aes_op.h"
#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"

// Generate random IV using ATECC608 RNG
ATCA_STATUS generate_iv(uint8_t* iv) {
    // Generate 16 random bytes for IV
    uint8_t random[32];
    ATCA_STATUS status = atcab_random(random);
    if (status != ATCA_SUCCESS) {
        printf("[aes] Failed to generate random IV: 0x%08X\n", status);

        // Retry once after delay
        sleep_ms(300);
        status = atcab_random(random);
        if (status != ATCA_SUCCESS) {
            printf("[aes] Retry to generate random IV failed: 0x%08X\n", status);
            return status;
        }
        printf("[aes] ✓ Random IV generated on retry\n");
    }
    memcpy(iv, random, 16);
    return status;
}

// AES-128 ECB Encryption/Decryption
ATCA_STATUS aes_ecb_encrypt(uint16_t key_slot,
                            const uint8_t* plaintext,
                            uint8_t* ciphertext)
{
    if (!plaintext || !ciphertext) {
        return ATCA_BAD_PARAM;
    }
    
    // ECB mode: block = 0, no chaining
    ATCA_STATUS status = atcab_aes_encrypt(key_slot, 0, plaintext, ciphertext);
    
    if (status != ATCA_SUCCESS) {
        printf("[aes] ECB encrypt failed: 0x%08X\n", status);
        
        // Retry once after delay
        sleep_ms(300);
        status = atcab_aes_encrypt(key_slot, 0, plaintext, ciphertext);
        if (status != ATCA_SUCCESS) {
            printf("[aes] ECB encrypt retry failed: 0x%08X\n", status);
            return status;
        }
        printf("[aes] ✓ ECB encrypt succeeded on retry\n");
    }
    
    return status;
}

// AES-128 ECB Decryption
ATCA_STATUS aes_ecb_decrypt(uint16_t key_slot,
                            const uint8_t* ciphertext,
                            uint8_t* plaintext)
{
    if (!ciphertext || !plaintext) {
        return ATCA_BAD_PARAM;
    }
    
    // ECB mode: block = 0, no chaining
    ATCA_STATUS status = atcab_aes_decrypt(key_slot, 0, ciphertext, plaintext);
    
    if (status != ATCA_SUCCESS) {
        printf("[aes] ECB decrypt failed: 0x%08X\n", status);
        
        // Retry once after delay
        sleep_ms(300);
        status = atcab_aes_decrypt(key_slot, 0, ciphertext, plaintext);
        if (status != ATCA_SUCCESS) {
            printf("[aes] ECB decrypt retry failed: 0x%08X\n", status);
            return status;
        }
        printf("[aes] ✓ ECB decrypt succeeded on retry\n");
    }
    
    return status;
}

// AES-128 CBC Encryption/Decryption
ATCA_STATUS aes_cbc_encrypt(uint16_t key_slot,
                            const uint8_t* iv,
                            const uint8_t* plaintext,
                            size_t plaintext_len,
                            uint8_t* ciphertext)
{
    if (!iv || !plaintext || !ciphertext) {
        return ATCA_BAD_PARAM;
    }
    
    // Check alignment (must be multiple of 16)
    if (plaintext_len % 16 != 0) {
        printf("[aes] CBC: plaintext length must be multiple of 16\n");
        return ATCA_BAD_PARAM;
    }
    
    ATCA_STATUS status;
    atca_aes_cbc_ctx_t ctx;
    
    // Initialize CBC mode
    status = atcab_aes_cbc_init(&ctx, key_slot, 0, iv);
    if (status != ATCA_SUCCESS) {
        printf("[aes] CBC init failed: 0x%08X\n", status);
        return status;
    }
    
    // Encrypt blocks
    size_t blocks = plaintext_len / 16;
    for (size_t i = 0; i < blocks; i++) {
        status = atcab_aes_cbc_encrypt_block(&ctx, 
                                            &plaintext[i * 16],
                                            &ciphertext[i * 16]);
        if (status != ATCA_SUCCESS) {
            printf("[aes] CBC encrypt block %zu failed: 0x%08X\n", i, status);
            
            // Give chip time to recover and retry once
            sleep_ms(300);
            
            // Reinitialize and retry from this block
            status = atcab_aes_cbc_init(&ctx, key_slot, 0, iv);
            if (status != ATCA_SUCCESS) {
                return status;
            }
            
            // Re-encrypt all blocks up to and including current one
            for (size_t j = 0; j <= i; j++) {
                status = atcab_aes_cbc_encrypt_block(&ctx,
                                                    &plaintext[j * 16],
                                                    &ciphertext[j * 16]);
                if (status != ATCA_SUCCESS) {
                    printf("[aes] CBC encrypt retry failed at block %zu: 0x%08X\n", j, status);
                    return status;
                }
            }
            printf("[aes] ✓ CBC encrypt succeeded on retry at block %zu\n", i);
        }
    }

    return ATCA_SUCCESS;
}


// AES-128 CBC Decryption
ATCA_STATUS aes_cbc_decrypt(uint16_t key_slot,
                            const uint8_t* iv,
                            const uint8_t* ciphertext,
                            size_t ciphertext_len,
                            uint8_t* plaintext)
{
    if (!iv || !ciphertext || !plaintext) {
        return ATCA_BAD_PARAM;
    }
    
    // Check alignment
    if (ciphertext_len % 16 != 0) {
        printf("[aes] CBC: ciphertext length must be multiple of 16\n");
        return ATCA_BAD_PARAM;
    }
    
    ATCA_STATUS status;
    atca_aes_cbc_ctx_t ctx;
    
    // Initialize CBC mode
    status = atcab_aes_cbc_init(&ctx, key_slot, 0, iv);
    if (status != ATCA_SUCCESS) {
        printf("[aes] CBC init failed: 0x%08X\n", status);
        return status;
    }
    
    // Decrypt blocks
    size_t blocks = ciphertext_len / 16;
    for (size_t i = 0; i < blocks; i++) {
        status = atcab_aes_cbc_decrypt_block(&ctx,
                                            &ciphertext[i * 16],
                                            &plaintext[i * 16]);
        if (status != ATCA_SUCCESS) {
            printf("[aes] CBC decrypt block %zu failed: 0x%08X\n", i, status);
            
            // Give chip time to recover and retry once
            sleep_ms(300);
            
            // Reinitialize and retry from this block
            status = atcab_aes_cbc_init(&ctx, key_slot, 0, iv);
            if (status != ATCA_SUCCESS) {
                return status;
            }
            
            // Re-decrypt all blocks up to and including current one
            for (size_t j = 0; j <= i; j++) {
                status = atcab_aes_cbc_decrypt_block(&ctx,
                                                    &ciphertext[j * 16],
                                                    &plaintext[j * 16]);
                if (status != ATCA_SUCCESS) {
                    printf("[aes] CBC decrypt retry failed at block %zu: 0x%08X\n", j, status);
                    return status;
                }
            }
            printf("[aes] ✓ CBC decrypt succeeded on retry at block %zu\n", i);
        }
    }
    
    return ATCA_SUCCESS;
}

// AES-128 GCM Encryption/Decryption
ATCA_STATUS aes_gcm_encrypt(uint16_t key_slot,
                            const uint8_t* iv,
                            size_t iv_len,
                            const uint8_t* aad,
                            size_t aad_len,
                            const uint8_t* plaintext,
                            size_t plaintext_len,
                            uint8_t* ciphertext,
                            uint8_t* tag)
{
    if (!iv || !plaintext || !ciphertext || !tag) {
        return ATCA_BAD_PARAM;
    }
    
    // Give chip time to finish any previous operation
    sleep_ms(50);
    
    ATCA_STATUS status;
    static atca_aes_gcm_ctx_t ctx;  // Static to avoid stack overflow
    
    // Initialize GCM context
    status = atcab_aes_gcm_init(&ctx, key_slot, 0, iv, iv_len);
    if (status != ATCA_SUCCESS) {
        printf("[aes] GCM init failed: 0x%08X\n", status);
        
        // Retry after delay
        sleep_ms(500);
        status = atcab_aes_gcm_init(&ctx, key_slot, 0, iv, iv_len);
        if (status != ATCA_SUCCESS) {
            printf("[aes] GCM init retry failed: 0x%08X\n", status);
            return status;
        }
        printf("[aes] ✓ GCM init succeeded on retry\n");
    }
    
    // Add AAD (Additional Authenticated Data) if provided
    if (aad && aad_len > 0) {
        status = atcab_aes_gcm_aad_update(&ctx, aad, aad_len);
        if (status != ATCA_SUCCESS) {
            printf("[aes] GCM AAD update failed: 0x%08X\n", status);
            
            // Retry entire operation
            sleep_ms(500);
            status = atcab_aes_gcm_init(&ctx, key_slot, 0, iv, iv_len);
            if (status == ATCA_SUCCESS) {
                status = atcab_aes_gcm_aad_update(&ctx, aad, aad_len);
            }
            if (status != ATCA_SUCCESS) {
                printf("[aes] GCM AAD retry failed: 0x%08X\n", status);
                return status;
            }
            printf("[aes] ✓ GCM AAD update succeeded on retry\n");
        }
    }
    
    // Encrypt data
    status = atcab_aes_gcm_encrypt_update(&ctx, plaintext, plaintext_len, ciphertext);
    if (status != ATCA_SUCCESS) {
        printf("[aes] GCM encrypt update failed: 0x%08X\n", status);
        
        // Retry entire operation
        sleep_ms(500);
        status = atcab_aes_gcm_init(&ctx, key_slot, 0, iv, iv_len);
        if (status == ATCA_SUCCESS && aad && aad_len > 0) {
            status = atcab_aes_gcm_aad_update(&ctx, aad, aad_len);
        }
        if (status == ATCA_SUCCESS) {
            status = atcab_aes_gcm_encrypt_update(&ctx, plaintext, plaintext_len, ciphertext);
        }
        if (status != ATCA_SUCCESS) {
            printf("[aes] GCM encrypt retry failed: 0x%08X\n", status);
            return status;
        }
        printf("[aes] ✓ GCM encrypt update succeeded on retry\n");
    }
    
    // Finalize and get tag
    status = atcab_aes_gcm_encrypt_finish(&ctx, tag, 16);
    if (status != ATCA_SUCCESS) {
        printf("[aes] GCM encrypt finish failed: 0x%08X\n", status);
        
        // Final retry
        sleep_ms(500);
        status = atcab_aes_gcm_init(&ctx, key_slot, 0, iv, iv_len);
        if (status == ATCA_SUCCESS && aad && aad_len > 0) {
            status = atcab_aes_gcm_aad_update(&ctx, aad, aad_len);
        }
        if (status == ATCA_SUCCESS) {
            status = atcab_aes_gcm_encrypt_update(&ctx, plaintext, plaintext_len, ciphertext);
        }
        if (status == ATCA_SUCCESS) {
            status = atcab_aes_gcm_encrypt_finish(&ctx, tag, 16);
        }
        if (status != ATCA_SUCCESS) {
            printf("[aes] GCM encrypt finish retry failed: 0x%08X\n", status);
            return status;
        }
        printf("[aes] ✓ GCM encrypt finish succeeded on retry\n");
    }
    
    return ATCA_SUCCESS;
}


// AES-128 GCM Decryption
ATCA_STATUS aes_gcm_decrypt(uint16_t key_slot,
                            const uint8_t* iv,
                            size_t iv_len,
                            const uint8_t* aad,
                            size_t aad_len,
                            const uint8_t* ciphertext,
                            size_t ciphertext_len,
                            const uint8_t* tag,
                            uint8_t* plaintext)
{
    printf("[aes] GCM decrypt START\n"); fflush(stdout);
    if (!iv || !ciphertext || !tag || !plaintext) {
        return ATCA_BAD_PARAM;
    }
    
    // Give chip time to finish any previous operation
    sleep_ms(50);
    printf("[aes] Sleeping 50ms...\n"); fflush(stdout);
    
    ATCA_STATUS status;
    static atca_aes_gcm_ctx_t ctx_decrypt;  // Static to avoid stack overflow
    bool is_verified = false;
    
    printf("[aes] About to call atcab_aes_gcm_init...\n"); fflush(stdout);
    // Initialize GCM context
    status = atcab_aes_gcm_init(&ctx_decrypt, key_slot, 0, iv, iv_len);
    printf("[aes] atcab_aes_gcm_init returned: 0x%08X\n", status); fflush(stdout);
    if (status != ATCA_SUCCESS) {
        printf("[aes] GCM init failed: 0x%08X\n", status);
        
        // Retry after delay
        sleep_ms(500);
        status = atcab_aes_gcm_init(&ctx_decrypt, key_slot, 0, iv, iv_len);
        if (status != ATCA_SUCCESS) {
            printf("[aes] GCM init retry failed: 0x%08X\n", status);
            return status;
        }
        printf("[aes] ✓ GCM init succeeded on retry\n");
    }
    
    // Add AAD if provided
    if (aad && aad_len > 0) {
        status = atcab_aes_gcm_aad_update(&ctx_decrypt, aad, aad_len);
        if (status != ATCA_SUCCESS) {
            printf("[aes] GCM AAD update failed: 0x%08X\n", status);
            
            // Retry entire operation
            sleep_ms(500);
            status = atcab_aes_gcm_init(&ctx_decrypt, key_slot, 0, iv, iv_len);
            if (status == ATCA_SUCCESS) {
                status = atcab_aes_gcm_aad_update(&ctx_decrypt, aad, aad_len);
            }
            if (status != ATCA_SUCCESS) {
                printf("[aes] GCM AAD retry failed: 0x%08X\n", status);
                return status;
            }
            printf("[aes] ✓ GCM AAD update succeeded on retry\n");
        }
    }
    
    // Decrypt data
    status = atcab_aes_gcm_decrypt_update(&ctx_decrypt, ciphertext, ciphertext_len, plaintext);
    if (status != ATCA_SUCCESS) {
        printf("[aes] GCM decrypt update failed: 0x%08X\n", status);
        
        // Retry entire operation
        sleep_ms(500);
        status = atcab_aes_gcm_init(&ctx_decrypt, key_slot, 0, iv, iv_len);
        if (status == ATCA_SUCCESS && aad && aad_len > 0) {
            status = atcab_aes_gcm_aad_update(&ctx_decrypt, aad, aad_len);
        }
        if (status == ATCA_SUCCESS) {
            status = atcab_aes_gcm_decrypt_update(&ctx_decrypt, ciphertext, ciphertext_len, plaintext);
        }
        if (status != ATCA_SUCCESS) {
            printf("[aes] GCM decrypt retry failed: 0x%08X\n", status);
            return status;
        }
        printf("[aes] ✓ GCM decrypt update succeeded on retry\n");
    }
    
    // Finalize and verify tag
    status = atcab_aes_gcm_decrypt_finish(&ctx_decrypt, tag, 16, &is_verified);
    if (status != ATCA_SUCCESS) {
        printf("[aes] GCM decrypt finish failed: 0x%08X\n", status);
        
        // Final retry
        sleep_ms(500);
        status = atcab_aes_gcm_init(&ctx_decrypt, key_slot, 0, iv, iv_len);
        if (status == ATCA_SUCCESS && aad && aad_len > 0) {
            status = atcab_aes_gcm_aad_update(&ctx_decrypt, aad, aad_len);
        }
        if (status == ATCA_SUCCESS) {
            status = atcab_aes_gcm_decrypt_update(&ctx_decrypt, ciphertext, ciphertext_len, plaintext);
        }
        if (status == ATCA_SUCCESS) {
            status = atcab_aes_gcm_decrypt_finish(&ctx_decrypt, tag, 16, &is_verified);
        }
        if (status != ATCA_SUCCESS) {
            printf("[aes] GCM decrypt finish retry failed: 0x%08X\n", status);
            return status;
        }
        printf("[aes] ✓ GCM decrypt finish succeeded on retry\n");
    }
    
    if (!is_verified) {
        printf("[aes] GCM authentication failed - tag mismatch!\n");
        return ATCA_CHECKMAC_VERIFY_FAILED;
    }
    
    return ATCA_SUCCESS;
}
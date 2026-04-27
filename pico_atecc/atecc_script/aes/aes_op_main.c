#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "cryptoauthlib.h"
#include "aes_op.h"

#define I2C_CONTROLLER      i2c0
#define I2C_SDA_PIN         4
#define I2C_SCL_PIN         5
#define I2C_FREQUENCY       100000

// ATECC608 I2C configuration
static ATCAIfaceCfg atecc_cfg = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype    = ATECC608B,
    .atcai2c    = {
        .address    = 0xC0 >> 1,
        .bus        = 0,
        .baud       = I2C_FREQUENCY
    },
    .wake_delay = 1500,
    .rx_retries = 1,
    .cfg_data   = NULL
};

// Helper to print data in hex format
static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s:\n  ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) {
            printf("\n  ");
        } else if (i < len - 1) {
            printf(" ");
        }
    }
    printf("\n");
}

// Helper to write a test AES key to a slot
static ATCA_STATUS write_test_key(uint16_t slot, const uint8_t* key) {
    // This assumes slot is writable (e.g., Slot 11 in dev mode)
    // For encrypted write, use calib_write_enc
    return atcab_write_zone(ATCA_ZONE_DATA, slot, 0, 0, key, 32);
}

int main(void) {
    stdio_init_all();
    sleep_ms(2000);
    
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  AES Operations Example              ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    // Initialize I2C
    i2c_init(I2C_CONTROLLER, I2C_FREQUENCY);
    gpio_set_function(I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SDA_PIN);
    gpio_pull_up(I2C_SCL_PIN);
    printf("\n[+] I2C initialized\n");
    
    // Initialize ATECC608
    ATCA_STATUS status = atcab_init(&atecc_cfg);
    if (status != ATCA_SUCCESS) {
        printf("[-] ATECC608 init failed: 0x%08X\n", status);
        return 1;
    }
    printf("[+] ATECC608 initialized\n");
    
    // Setup: Write test AES key to Slot 11 (assuming it's writable)
    printf("\n[+] Setting up test AES key in Slot 11\n");
    uint8_t test_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    
    // Write the key
    status = write_test_key(11, test_key);
    if (status != ATCA_SUCCESS) {
        printf("[-] Failed to write test key (Slot 11 may not be writable)\n");
        printf("    Continuing anyway - operations may fail\n");
    } else {
        printf("[+] Test key written to Slot 11\n");
    }
    
    // Test data
    uint8_t plaintext[16] = {
        'H','e','l','l','o',' ','A','E','S','-','G','C','M','!','!','!'
    };
    
    printf("\n");
    print_hex("Original Plaintext", plaintext, 16);
    
    // ===================================================================
    // Test 1: AES-128 ECB Encryption/Decryption
    // ===================================================================
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  Test 1: AES-128 ECB                 ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    uint8_t ecb_ciphertext[16];
    uint8_t ecb_decrypted[16];
    
    // Encrypt
    status = aes_ecb_encrypt(11, plaintext, ecb_ciphertext);
    if (status == ATCA_SUCCESS) {
        printf("[+] ECB Encryption succeeded\n");
        print_hex("ECB Ciphertext", ecb_ciphertext, 16);
        
        // Decrypt
        status = aes_ecb_decrypt(11, ecb_ciphertext, ecb_decrypted);
        if (status == ATCA_SUCCESS) {
            print_hex("ECB Decrypted", ecb_decrypted, 16);
            
            if (memcmp(plaintext, ecb_decrypted, 16) == 0) {
                printf("[+] ✅ ECB round-trip successful!\n");
            } else {
                printf("[-] ECB decryption mismatch\n");
            }
        } else {
            printf("[-] ECB decryption failed\n");
        }
    } else {
        printf("[-] ECB encryption failed\n");
    }
    
    // ===================================================================
    // Test 2: AES-128 CBC Encryption/Decryption
    // ===================================================================
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  Test 2: AES-128 CBC                 ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    };
    
    // Multiple blocks for CBC
    uint8_t cbc_plaintext[32];
    memcpy(cbc_plaintext, plaintext, 16);
    memcpy(cbc_plaintext + 16, plaintext, 16);
    
    uint8_t cbc_ciphertext[32];
    uint8_t cbc_decrypted[32];
    
    print_hex("IV", iv, 16);
    
    // Encrypt
    status = aes_cbc_encrypt(11, iv, cbc_plaintext, 32, cbc_ciphertext);
    if (status == ATCA_SUCCESS) {
        printf("[+] CBC Encryption succeeded\n");
        print_hex("CBC Ciphertext", cbc_ciphertext, 32);
        
        // Decrypt
        status = aes_cbc_decrypt(11, iv, cbc_ciphertext, 32, cbc_decrypted);
        if (status == ATCA_SUCCESS) {
            print_hex("CBC Decrypted", cbc_decrypted, 32);
            
            if (memcmp(cbc_plaintext, cbc_decrypted, 32) == 0) {
                printf("[+] ✅ CBC round-trip successful!\n");
            } else {
                printf("[-] CBC decryption mismatch\n");
            }
        } else {
            printf("[-] CBC decryption failed\n");
        }
    } else {
        printf("[-] CBC encryption failed\n");
    }
    
    // ===================================================================
    // Test 3: AES-128 GCM Encryption/Decryption
    // ===================================================================
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  Test 3: AES-128 GCM (Authenticated) ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    uint8_t gcm_iv[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B
    };
    
    // Additional Authenticated Data (AAD)
    uint8_t aad[] = "Additional Data";
    uint8_t gcm_ciphertext[16];
    uint8_t gcm_tag[16];
    uint8_t gcm_decrypted[16];
    
    print_hex("GCM IV", gcm_iv, 12);
    printf("AAD: %s\n", aad);
    
    // Encrypt
    status = aes_gcm_encrypt(11, gcm_iv, 12, aad, strlen((char*)aad),
                            plaintext, 16, gcm_ciphertext, gcm_tag);
    if (status == ATCA_SUCCESS) {
        printf("[+] GCM Encryption succeeded\n");
        print_hex("GCM Ciphertext", gcm_ciphertext, 16);
        print_hex("GCM Tag", gcm_tag, 16);
        
        // Decrypt and verify
        status = aes_gcm_decrypt(11, gcm_iv, 12, aad, strlen((char*)aad),
                                gcm_ciphertext, 16, gcm_tag, gcm_decrypted);
        if (status == ATCA_SUCCESS) {
            print_hex("GCM Decrypted", gcm_decrypted, 16);
            
            if (memcmp(plaintext, gcm_decrypted, 16) == 0) {
                printf("[+] ✅ GCM round-trip and authentication successful!\n");
            } else {
                printf("[-] GCM decryption mismatch\n");
            }
        } else {
            printf("[-] GCM decryption/authentication failed\n");
        }
        
        // Test authentication failure with wrong tag
        printf("\n[+] Testing authentication with wrong tag...\n");
        uint8_t wrong_tag[16];
        memcpy(wrong_tag, gcm_tag, 16);
        wrong_tag[0] ^= 0xFF; // Corrupt first byte
        
        status = aes_gcm_decrypt(11, gcm_iv, 12, aad, strlen((char*)aad),
                                gcm_ciphertext, 16, wrong_tag, gcm_decrypted);
        if (status != ATCA_SUCCESS) {
            printf("[+] ✅ Authentication correctly failed with wrong tag\n");
        } else {
            printf("[-] WARNING: Authentication did not detect wrong tag!\n");
        }
        
    } else {
        printf("[-] GCM encryption failed\n");
    }
    
    // Summary
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  Summary                             ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    printf("\n✅ AES Operations Demo Complete!\n");
    printf("\n📋 Modes Tested:\n");
    printf("  • ECB - Electronic Codebook (simple, no IV)\n");
    printf("  • CBC - Cipher Block Chaining (with IV)\n");
    printf("  • GCM - Galois/Counter Mode (authenticated)\n");
    
    printf("\n💡 Best Practices:\n");
    printf("  • Use GCM for authenticated encryption\n");
    printf("  • CBC for bulk encryption with IV\n");
    printf("  • Avoid ECB for multi-block data\n");
    printf("  • Always use unique IVs per encryption\n");
    
    atcab_release();
    
    printf("\n[+] Demo complete!\n\n");
    
    while (true) {
        tight_loop_contents();
    }
    
    return 0;
}
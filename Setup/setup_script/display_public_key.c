/**
 * @file main.c
 * @brief Print public keys from Slots 0-3
 * @date 2025
 */

#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "cryptoauthlib.h"

#define I2C_CONTROLLER      i2c0
#define I2C_SDA_PIN         4
#define I2C_SCL_PIN         5
#define I2C_FREQUENCY       100000

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

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s:\n", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0 && i < len - 1) {
            printf("\n");
        }
    }
    printf("\n");
}

int main(void) {
    stdio_init_all();
    sleep_ms(2000);
    
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  ATECC608A Public Key Reader         ║\n");
    printf("║  Slots 0-3                           ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    // Initialize I2C
    i2c_init(I2C_CONTROLLER, I2C_FREQUENCY);
    gpio_set_function(I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SDA_PIN);
    gpio_pull_up(I2C_SCL_PIN);
    printf("\n✅ I2C initialized\n");
    
    // Initialize ATECC608
    ATCA_STATUS status = atcab_init(&atecc_cfg);
    if (status != ATCA_SUCCESS) {
        printf("❌ ATECC608 init failed: 0x%08X\n", status);
        return 1;
    }
    printf("✅ ATECC608 initialized\n\n");
    
    // Read public keys from Slots 0-3
    for (int slot = 0; slot <= 3; slot++) {
        printf("═══════════════════════════════════════\n");
        printf("  Slot %d\n", slot);
        printf("═══════════════════════════════════════\n");
        
        uint8_t public_key[64];
        status = atcab_get_pubkey(slot, public_key);
        
        if (status == ATCA_SUCCESS) {
            printf("✅ Public Key Found:\n");
            print_hex("  ", public_key, 64);
            
            // Print X and Y coordinates separately
            printf("\nX coordinate (32 bytes):\n  ");
            for (int i = 0; i < 32; i++) {
                printf("%02X", public_key[i]);
            }
            printf("\n");
            
            printf("Y coordinate (32 bytes):\n  ");
            for (int i = 32; i < 64; i++) {
                printf("%02X", public_key[i]);
            }
            printf("\n");
            
        } else if (status == ATCA_EXECUTION_ERROR) {
            printf("⚠️  No key in this slot (empty)\n");
        } else {
            printf("❌ Failed to read public key: 0x%08X\n", status);
        }
        
        printf("\n");
    }
    
    printf("═══════════════════════════════════════\n");
    printf("  Summary\n");
    printf("═══════════════════════════════════════\n\n");
    
    printf("✅ Public key reading complete!\n");
    printf("\n💡 Notes:\n");
    printf("  • Slots 0-3 typically contain ECC P-256 keys\n");
    printf("  • Public key format: 0x04 || X || Y (65 bytes uncompressed)\n");
    printf("  • Display shows X and Y as 32 bytes each\n");
    printf("  • Empty slots show execution error\n");
    
    atcab_release();
    
    printf("\n✅ Done!\n\n");
    
    while (true) {
        tight_loop_contents();
    }
    
    return 0;
}
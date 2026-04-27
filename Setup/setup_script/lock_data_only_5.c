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

int main(void) {
    stdio_init_all();
    sleep_ms(2000);
    
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  Lock Data Zone                      ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    // Initialize
    i2c_init(I2C_CONTROLLER, I2C_FREQUENCY);
    gpio_set_function(I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SDA_PIN);
    gpio_pull_up(I2C_SCL_PIN);
    printf("\n✅ I2C initialized\n");
    
    ATCA_STATUS status = atcab_init(&atecc_cfg);
    if (status != ATCA_SUCCESS) {
        printf("❌ Init failed: 0x%08X\n", status);
        return 1;
    }
    printf("✅ CryptoAuthLib initialized\n");
    
    // Check current lock status
    printf("\n--- Checking Current Status ---\n");
    uint8_t config[128];
    status = atcab_read_config_zone(config);
    if (status != ATCA_SUCCESS) {
        printf("❌ Cannot read config: 0x%08X\n", status);
        atcab_release();
        return 1;
    }
    
    uint8_t config_lock = config[87];
    uint8_t data_lock = config[86];
    
    printf("ConfigLock: 0x%02X %s\n", config_lock,
           config_lock == 0x00 ? "🔒 LOCKED" : "🔓 UNLOCKED");
    printf("DataLock:   0x%02X %s\n", data_lock,
           data_lock == 0x00 ? "🔒 LOCKED" : "🔓 UNLOCKED");
    
    // Check if already locked
    if (data_lock == 0x00) {
        printf("\n✅ Data zone is already LOCKED!\n");
        printf("Nothing to do.\n");
        atcab_release();
        
        while (true) {
            tight_loop_contents();
        }
        return 0;
    }
    
    // Warning
    printf("\n");
    printf("═══════════════════════════════════════\n");
    printf("  ⚠️  WARNING ⚠️\n");
    printf("═══════════════════════════════════════\n");
    printf("\nYou are about to LOCK the data zone.\n");
    printf("\nThis is PERMANENT and IRREVERSIBLE!\n");
    printf("\nAfter locking:\n");
    printf("  ✅ AES operations will work\n");
    printf("  ✅ Encrypted writes still allowed\n");
    printf("  ✅ Crypto operations enabled\n");
    printf("  ❌ Cannot do plain writes\n");
    printf("  ❌ Cannot unlock ever again\n");
    
    printf("\n🔐 Locking in 5 seconds...\n");
    printf("⚠️  UNPLUG NOW TO CANCEL!\n\n");
    
    for (int i = 5; i > 0; i--) {
        printf("  %d...\n", i);
        sleep_ms(1000);
    }
    
    printf("\n🔒 LOCKING DATA ZONE...\n");
    status = atcab_lock_data_zone();
    
    if (status == ATCA_SUCCESS) {
        printf("\n✅✅✅ DATA ZONE LOCKED! ✅✅✅\n");
        printf("\nDataLock is now 0x00 (permanent)\n");
        
        // Verify
        status = atcab_read_config_zone(config);
        if (status == ATCA_SUCCESS) {
            data_lock = config[86];
            printf("Verified: DataLock = 0x%02X %s\n", data_lock,
                   data_lock == 0x00 ? "✅" : "⚠️");
        }
        
        printf("\n🎉 Success! You can now:\n");
        printf("  • Use AES operations on Slot 9\n");
        printf("  • Perform crypto operations\n");
        printf("  • Update keys via encrypted write\n");
        
    } else {
        printf("\n❌ LOCK FAILED: 0x%08X\n", status);
        printf("\nPossible reasons:\n");
        printf("  • ConfigLock not set (must lock config first)\n");
        printf("  • Communication error\n");
        printf("  • Already locked\n");
    }
    
    atcab_release();
    
    printf("\n");
    printf("╔══════════════════════════════════════╗\n");
    printf("║  Complete                            ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    while (true) {
        tight_loop_contents();
    }
    
    return 0;
}
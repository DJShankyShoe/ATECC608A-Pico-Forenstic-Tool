#include "atecc.h"
#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/gpio.h"

// ATECC608 Interface Configuration
static ATCAIfaceCfg atecc_cfg = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype    = ATECC608B,
    .atcai2c    = {
        .address    = ATECC_I2C_ADDRESS,
        .bus        = 0,
        .baud       = ATECC_I2C_FREQUENCY
    },
    .wake_delay = ATECC_WAKE_DELAY,
    .rx_retries = ATECC_RX_RETRIES,
    .cfg_data   = NULL
};

// Initialization state
static bool atecc_initialized = false;

/**
 * Initialize I2C bus with proper configuration
 */
static bool atecc_init_i2c(void) {
    printf("[ATECC] Initializing I2C bus...\n");
    
    // Initialize I2C peripheral
    uint32_t actual_baud = i2c_init(ATECC_I2C_CONTROLLER, ATECC_I2C_FREQUENCY);
    printf("[ATECC] I2C initialized at %u Hz (requested %u Hz)\n", 
           actual_baud, ATECC_I2C_FREQUENCY);
    
    // Configure GPIO pins for I2C
    gpio_set_function(ATECC_I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(ATECC_I2C_SCL_PIN, GPIO_FUNC_I2C);
    
    // Enable pull-ups (required for I2C)
    gpio_pull_up(ATECC_I2C_SDA_PIN);
    gpio_pull_up(ATECC_I2C_SCL_PIN);
    
    printf("[ATECC] I2C pins configured (SDA=%d, SCL=%d)\n", 
           ATECC_I2C_SDA_PIN, ATECC_I2C_SCL_PIN);
    
    return true;
}

// Initialize the ATECC608 chip
bool atecc_init(void) {
    printf("\n[ATECC] ========================================\n");
    printf("[ATECC] Initializing ATECC608B Cryptographic Chip\n");
    printf("[ATECC] ========================================\n");
    
    // Check if already initialized
    if (atecc_initialized) {
        printf("[ATECC] ⚠️  Already initialized\n");
        return true;
    }
    
    // Step 1: Initialize I2C bus
    if (!atecc_init_i2c()) {
        printf("[ATECC] ✗ I2C initialization failed\n");
        return false;
    }
    
    // Step 2: Initialize ATECC608 library
    printf("[ATECC] Initializing ATECC608 library...\n");
    ATCA_STATUS status = atcab_init(&atecc_cfg);
    
    if (status != ATCA_SUCCESS) {
        printf("[ATECC] ✗ ATECC608 init failed: 0x%08X\n", status);
        printf("[ATECC] Common causes:\n");
        printf("[ATECC]   - Chip not connected\n");
        printf("[ATECC]   - Incorrect I2C address (current: 0x%02X)\n", 
               ATECC_I2C_ADDRESS);
        printf("[ATECC]   - Bad wiring or pull-ups\n");
        printf("[ATECC]   - Power supply issues\n");
        return false;
    }
    
    printf("[ATECC] ✓ ATECC608 library initialized\n");
    
    // Step 3: Verify communication
    printf("[ATECC] Verifying communication...\n");
    if (!atecc_verify_communication()) {
        printf("[ATECC] ✗ Communication verification failed\n");
        atcab_release();
        return false;
    }
    
    atecc_initialized = true;
    
    printf("[ATECC] ========================================\n");
    printf("[ATECC] ✓ ATECC608B Ready\n");
    printf("[ATECC] ========================================\n\n");
    
    return true;
}

// Deinitialize the ATECC608 chip
void atecc_deinit(void) {
    if (atecc_initialized) {
        printf("[ATECC] Deinitializing ATECC608...\n");
        atcab_release();
        atecc_initialized = false;
        printf("[ATECC] ✓ ATECC608 deinitialized\n");
    }
}

// Check if ATECC608 is ready for operations
bool atecc_is_ready(void) {
    if (!atecc_initialized) {
        return false;
    }
    
    // Quick communication check using Info command
    uint8_t revision[4];
    ATCA_STATUS status = atcab_info(revision);
    
    return (status == ATCA_SUCCESS);
}

// Get pointer to ATECC608 configuration
ATCAIfaceCfg* atecc_get_cfg(void) {
    return &atecc_cfg;
}

// Verify communication with ATECC608 chip
bool atecc_verify_communication(void) {
    // Use Info command to verify chip is responding
    uint8_t revision[4];
    ATCA_STATUS status = atcab_info(revision);
    
    if (status != ATCA_SUCCESS) {
        printf("[ATECC] Communication test failed: 0x%08X\n", status);
        return false;
    }
    
    printf("[ATECC] ✓ Communication verified\n");
    printf("[ATECC] Chip revision: %02X %02X %02X %02X\n", 
           revision[0], revision[1], revision[2], revision[3]);
    
    return true;
}

// Print detailed information about the ATECC608 chip
bool atecc_print_info(void) {
    if (!atecc_initialized) {
        printf("[ATECC] ✗ Not initialized\n");
        return false;
    }
    
    printf("\n[ATECC] ========================================\n");
    printf("[ATECC] Device Information\n");
    printf("[ATECC] ========================================\n");
    
    // Get revision
    uint8_t revision[4];
    ATCA_STATUS status = atcab_info(revision);
    if (status == ATCA_SUCCESS) {
        printf("[ATECC] Revision:    %02X %02X %02X %02X\n", 
               revision[0], revision[1], revision[2], revision[3]);
    } else {
        printf("[ATECC] Revision:    Failed to read (0x%08X)\n", status);
    }
    
    // Get serial number
    uint8_t serial[9];
    status = atcab_read_serial_number(serial);
    if (status == ATCA_SUCCESS) {
        printf("[ATECC] Serial:      ");
        for (int i = 0; i < 9; i++) {
            printf("%02X", serial[i]);
        }
        printf("\n");
    } else {
        printf("[ATECC] Serial:      Failed to read (0x%08X)\n", status);
    }
    
    // Check lock status
    bool config_locked = false;
    bool data_locked = false;
    
    status = atcab_is_locked(LOCK_ZONE_CONFIG, &config_locked);
    if (status == ATCA_SUCCESS) {
        printf("[ATECC] Config Zone: %s\n", config_locked ? "🔒 Locked" : "🔓 Unlocked");
    } else {
        printf("[ATECC] Config Zone: Failed to read (0x%08X)\n", status);
    }
    
    status = atcab_is_locked(LOCK_ZONE_DATA, &data_locked);
    if (status == ATCA_SUCCESS) {
        printf("[ATECC] Data Zone:   %s\n", data_locked ? "🔒 Locked" : "🔓 Unlocked");
    } else {
        printf("[ATECC] Data Zone:   Failed to read (0x%08X)\n", status);
    }
    
    printf("[ATECC] ========================================\n\n");
    
    return true;
}
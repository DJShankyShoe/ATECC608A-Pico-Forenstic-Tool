#ifndef ATECC_H
#define ATECC_H

#include <stdbool.h>
#include "hardware/i2c.h"
#include "cryptoauthlib.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

// I2C Configuration
#define ATECC_I2C_CONTROLLER    i2c0
#define ATECC_I2C_SDA_PIN       4
#define ATECC_I2C_SCL_PIN       5
#define ATECC_I2C_FREQUENCY     100000      // 100 kHz

// ATECC608 I2C Address
#define ATECC_I2C_ADDRESS       (0xC0 >> 1) // 0x60

// Timing Configuration
#define ATECC_WAKE_DELAY        1500        // Wake delay in microseconds
#define ATECC_RX_RETRIES        1           // Number of retries

// ============================================================================
// FUNCTION DECLARATIONS
// ============================================================================

/**
 * Initialize ATECC608 cryptographic chip
 * 
 * This function:
 * - Initializes I2C bus with pull-ups
 * - Configures ATECC608 interface
 * - Performs wake sequence
 * - Verifies communication
 * 
 * @return true if initialization successful, false otherwise
 */
bool atecc_init(void);

/**
 * Deinitialize ATECC608 and release resources
 */
void atecc_deinit(void);

/**
 * Check if ATECC608 is initialized and responsive
 * 
 * @return true if chip is initialized and responding, false otherwise
 */
bool atecc_is_ready(void);

/**
 * Get the ATECC608 configuration structure
 * 
 * @return Pointer to the ATCAIfaceCfg structure
 */
ATCAIfaceCfg* atecc_get_cfg(void);

/**
 * Print ATECC608 device information
 * Displays serial number, revision, and configuration zone lock status
 * 
 * @return true if info retrieved successfully, false otherwise
 */
bool atecc_print_info(void);

/**
 * Verify ATECC608 communication with Info command
 * 
 * @return true if communication successful, false otherwise
 */
bool atecc_verify_communication(void);

#endif // ATECC_INIT_H
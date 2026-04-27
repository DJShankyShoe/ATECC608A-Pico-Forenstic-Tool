#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "hardware/gpio.h"
#include "cryptoauthlib.h"

// =============================================================================
// CONFIGURATION SECTION
// =============================================================================

// I2C Configuration for ATECC608
#define PICO_I2C_PERIPHERAL     i2c0
#define PICO_I2C_SDA_GPIO       4
#define PICO_I2C_SCL_GPIO       5
#define PICO_I2C_CLOCK_HZ       100000
#define ATECC608_I2C_ADDR       0x60

#define ENABLE_HAL_DEBUG        0

#if ENABLE_HAL_DEBUG
    #define HAL_LOG(...) printf("[ATECCX08-HAL] " __VA_ARGS__)
#else
    #define HAL_LOG(...)
#endif

// =============================================================================
// MEMORY ALLOCATION INTERFACE
// =============================================================================

// Custom memory allocation functions using standard malloc/free
void* hal_malloc(size_t size) {
    return malloc(size);
}

void hal_free(void* ptr) {
    if (ptr != NULL) {
        free(ptr);
    }
}

// =============================================================================
// TIMING INTERFACE
// =============================================================================


// Provides millisecond and microsecond delays
void hal_delay_ms(uint32_t delay_ms) {
    sleep_ms(delay_ms);
}

void hal_delay_us(uint32_t delay_us) {
    sleep_us(delay_us);
}

// Legacy naming for compatibility
void atca_delay_ms(uint32_t ms) { hal_delay_ms(ms); }
void atca_delay_us(uint32_t us) { hal_delay_us(us); }

// =============================================================================
// GPIO-BASED WAKE PULSE GENERATOR
// =============================================================================

/**
 * @brief Generates wake pulse by bit-banging SDA line
 * 
 * The ATECC608 requires a low pulse on SDA for 60μs minimum to wake from
 * sleep mode. This function temporarily converts SDA to a GPIO output,
 * generates the pulse, then restores I2C functionality.
 */
static void execute_wake_pulse_sequence(void) {
    HAL_LOG("Executing wake pulse sequence\n");
    
    // Step 1: Convert SDA pin to general-purpose output
    gpio_set_function(PICO_I2C_SDA_GPIO, GPIO_FUNC_SIO);
    gpio_set_dir(PICO_I2C_SDA_GPIO, GPIO_OUT);
    
    // Step 2: Drive SDA low for wake pulse (80μs for safety margin)
    gpio_put(PICO_I2C_SDA_GPIO, 0);
    sleep_us(80);
    
    // Step 3: Release SDA line
    gpio_put(PICO_I2C_SDA_GPIO, 1);
    
    // Step 4: Restore I2C functionality on SDA pin
    gpio_set_function(PICO_I2C_SDA_GPIO, GPIO_FUNC_I2C);
    gpio_pull_up(PICO_I2C_SDA_GPIO);
    
    // Step 5: Wait for device wake time (tWHI)
    sleep_us(1500);
    
    HAL_LOG("Wake pulse complete\n");
}

// =============================================================================
// HAL INTERFACE IMPLEMENTATIONS
// =============================================================================

/**
 * @brief Initialize I2C hardware interface
 * 
 * Sets up the I2C peripheral with appropriate clock speed and configures
 * GPIO pins for I2C operation with pull-ups enabled.
 */
ATCA_STATUS hal_i2c_init(ATCAIface iface, ATCAIfaceCfg* cfg) {
    HAL_LOG("Initializing I2C interface\n");
    
    // Configure I2C peripheral
    i2c_init(PICO_I2C_PERIPHERAL, PICO_I2C_CLOCK_HZ);
    
    // Configure GPIO pins for I2C function
    gpio_set_function(PICO_I2C_SDA_GPIO, GPIO_FUNC_I2C);
    gpio_set_function(PICO_I2C_SCL_GPIO, GPIO_FUNC_I2C);
    
    // Enable internal pull-ups (external pull-ups still recommended!)
    gpio_pull_up(PICO_I2C_SDA_GPIO);
    gpio_pull_up(PICO_I2C_SCL_GPIO);
    
    HAL_LOG("I2C initialized: %d kHz on GP%d(SDA)/GP%d(SCL)\n", 
            PICO_I2C_CLOCK_HZ / 1000, PICO_I2C_SDA_GPIO, PICO_I2C_SCL_GPIO);
    
    return ATCA_SUCCESS;
}

/**
 * @brief Post-initialization hook (no action required for Pico)
 */
ATCA_STATUS hal_i2c_post_init(ATCAIface iface) {
    HAL_LOG("Post-init called\n");
    return ATCA_SUCCESS;
}

/**
 * @brief Transmit data to ATECC608 over I2C
 * 
 * Handles three scenarios:
 * 1. Wake command (address 0x00): Generates GPIO wake pulse
 * 2. Command packet: Prepends word address and transmits
 * 3. Raw transmission: Direct I2C write
 * 
 * Note: This function does NOT read the wake response - that's handled
 * by subsequent receive calls from CryptoAuthLib.
 */
ATCA_STATUS hal_i2c_send(ATCAIface iface, uint8_t word_addr, uint8_t* txdata, int txlen) {
    HAL_LOG("TX: word_addr=0x%02X, len=%d\n", word_addr, txlen);
    
    // Scenario 1: Wake command detection
    // CryptoAuthLib signals wake by writing to address 0x00 with zero length
    if (word_addr == 0x00 && txlen == 0) {
        execute_wake_pulse_sequence();
        return ATCA_SUCCESS;
    }
    
    // Validate transmission parameters
    if (txdata == NULL || txlen <= 0) {
        HAL_LOG("ERROR: Invalid parameters\n");
        return ATCA_BAD_PARAM;
    }
    
    // Scenario 2 & 3: Command transmission
    // Build packet with word address prefix
    uint8_t packet_buffer[257];  // Max packet: 1 byte addr + 256 bytes data
    packet_buffer[0] = word_addr;
    memcpy(&packet_buffer[1], txdata, txlen);
    
    int total_bytes = txlen + 1;
    
    #if ENABLE_HAL_DEBUG
    HAL_LOG("TX packet: ");
    for (int i = 0; i < total_bytes && i < 12; i++) {
        printf("%02X ", packet_buffer[i]);
    }
    if (total_bytes > 12) printf("...");
    printf("\n");
    #endif
    
    // Execute I2C write operation
    int bytes_written = i2c_write_blocking(PICO_I2C_PERIPHERAL, ATECC608_I2C_ADDR,
                                           packet_buffer, total_bytes, false);
    
    if (bytes_written == total_bytes) {
        HAL_LOG("TX complete: %d bytes\n", bytes_written);
        return ATCA_SUCCESS;
    } else {
        HAL_LOG("TX FAILED: wrote %d of %d bytes\n", bytes_written, total_bytes);
        return ATCA_COMM_FAIL;
    }
}

/**
 * @brief Receive data from ATECC608 over I2C with polling
 * 
 * Polls the device for response data with appropriate delays. The ATECC608
 * requires time to process commands (Random command takes up to 23ms), so
 * this function implements a polling loop with delays between attempts.
 * 
 * This approach ensures the device has time to complete command execution
 * before attempting subsequent reads.
 */
ATCA_STATUS hal_i2c_receive(ATCAIface iface, uint8_t word_addr, uint8_t* rxdata, uint16_t* rxlen) {
    HAL_LOG("RX: expecting %d bytes from addr 0x%02X\n", rxlen ? *rxlen : 0, word_addr);
    
    // Validate receive parameters
    if (rxdata == NULL || rxlen == NULL || *rxlen == 0) {
        HAL_LOG("ERROR: Invalid receive parameters\n");
        return ATCA_BAD_PARAM;
    }
    
    uint16_t expected_bytes = *rxlen;
    
    // Poll for response with delays (device needs time to process commands)
    // Maximum attempts: 50 iterations × 10ms = 500ms timeout
    const int max_poll_attempts = 50;
    const int poll_delay_ms = 10;
    
    for (int attempt = 0; attempt < max_poll_attempts; attempt++) {
        // Execute I2C read operation
        int bytes_read = i2c_read_blocking(PICO_I2C_PERIPHERAL, word_addr,
                                           rxdata, expected_bytes, false);
        
        if (bytes_read == expected_bytes) {
            // Check if this is a wake response (04 11 33 43)
            // If so, skip it and continue polling for actual command response
            if (expected_bytes >= 4 && 
                rxdata[0] == 0x04 && rxdata[1] == 0x11 && 
                rxdata[2] == 0x33 && rxdata[3] == 0x43) {
                HAL_LOG("RX: wake response detected, continuing poll...\n");
                sleep_us(1500);  // tWHI delay after wake response
                continue;
            }
            
            // Successful read of command response
            #if ENABLE_HAL_DEBUG
            HAL_LOG("RX success (attempt %d): ", attempt);
            for (int i = 0; i < bytes_read && i < 12; i++) {
                printf("%02X ", rxdata[i]);
            }
            if (bytes_read > 12) printf("...");
            printf("\n");
            #endif
            return ATCA_SUCCESS;
            
        } else if (bytes_read > 0 && bytes_read < expected_bytes) {
            // Partial read - likely a real error, not just busy
            HAL_LOG("RX partial: got %d of %d bytes\n", bytes_read, expected_bytes);
            *rxlen = bytes_read;
            return ATCA_COMM_FAIL;
            
        } else {
            // NACK or timeout - device is busy processing command
            // Wait before retrying (only log first few attempts to avoid spam)
            if (attempt < 3) {
                HAL_LOG("RX attempt %d: device busy, retrying...\n", attempt);
            }
            sleep_ms(poll_delay_ms);
        }
    }
    
    // Timeout after all retry attempts
    HAL_LOG("RX TIMEOUT after %d attempts\n", max_poll_attempts);
    return ATCA_RX_TIMEOUT;
}

/**
 * @brief Control interface for special operations
 * 
 * Handles wake/idle/sleep commands via control opcodes. Currently only
 * wake is explicitly implemented; other operations return success to
 * avoid breaking the communication flow.
 */
ATCA_STATUS hal_i2c_control(ATCAIface iface, uint8_t opcode, void* param, size_t paramlen) {
    HAL_LOG("Control: opcode=0x%02X\n", opcode);
    
    switch (opcode) {
        case ATCA_HAL_CONTROL_WAKE:
            execute_wake_pulse_sequence();
            return ATCA_SUCCESS;
            
        case ATCA_HAL_CONTROL_IDLE:
            HAL_LOG("Idle command (no-op)\n");
            return ATCA_SUCCESS;
            
        case ATCA_HAL_CONTROL_SLEEP:
            HAL_LOG("Sleep command (no-op)\n");
            return ATCA_SUCCESS;
            
        default:
            HAL_LOG("Unhandled control opcode\n");
            return ATCA_UNIMPLEMENTED;
    }
}

/**
 * @brief Release HAL resources (no-op for Pico)
 */
ATCA_STATUS hal_i2c_release(void* hal_data) {
    HAL_LOG("Release called\n");
    return ATCA_SUCCESS;
}

/**
 * @brief Discover available I2C buses
 */
ATCA_STATUS hal_i2c_discover_buses(int* buses_found, int max_buses) {
    if (buses_found) {
        *buses_found = 1;  // Pico has i2c0 and i2c1, but we only use i2c0
    }
    return ATCA_SUCCESS;
}

/**
 * @brief Discover devices on I2C bus
 */
ATCA_STATUS hal_i2c_discover_devices(int bus_num, uint8_t* devices_found, int max_devices) {
    if (devices_found && max_devices > 0) {
        // Attempt zero-byte write to check device presence
        uint8_t dummy = 0;
        int result = i2c_write_timeout_us(PICO_I2C_PERIPHERAL, ATECC608_I2C_ADDR,
                                          &dummy, 0, false, 100000);
        if (result >= 0) {
            devices_found[0] = ATECC608_I2C_ADDR;
            return ATCA_SUCCESS;
        }
    }
    return ATCA_COMM_FAIL;
}
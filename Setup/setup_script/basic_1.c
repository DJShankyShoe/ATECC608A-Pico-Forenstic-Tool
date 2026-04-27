/**
 * 1. Reading the unique 9-byte serial number
 * 2. Generating cryptographically secure random numbers
 */

#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "cryptoauthlib.h"

// =============================================================================
// I2C HARDWARE CONFIGURATION
// =============================================================================

#define I2C_CONTROLLER      i2c0
#define I2C_SDA_PIN_NUM     4
#define I2C_SCL_PIN_NUM     5
#define I2C_FREQUENCY_HZ    100000

// =============================================================================
// ATECC608 DEVICE CONFIGURATION
// =============================================================================

static ATCAIfaceCfg atecc608_interface_config = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype    = ATECC608B,
    .atcai2c    = {
        .address    = 0xC0 >> 1,    // Convert 8-bit to 7-bit address
        .bus        = 0,
        .baud       = I2C_FREQUENCY_HZ
    },
    .wake_delay = 1500,
    .rx_retries = 1,                // HAL handles polling internally now
    .cfg_data   = NULL
};

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

/**
 * @brief Print buffer contents in hexadecimal format
 * @param label Descriptive label for the data
 * @param data Pointer to data buffer
 * @param length Number of bytes to print
 */
static void print_hex_buffer(const char* label, const uint8_t* data, size_t length) {
    printf("%s: ", label);
    for (size_t i = 0; i < length; i++) {
        printf("%02X", data[i]);
        if (i < length - 1) {
            // Add space every 4 bytes for readability
            if ((i + 1) % 4 == 0) {
                printf(" ");
            }
        }
    }
    printf("\n");
}

/**
 * @brief Print test section header
 * @param title Test section title
 */
static void print_section_header(const char* title) {
    printf("\n");
    printf("========================================\n");
    printf("  %s\n", title);
    printf("========================================\n");
}

/**
 * @brief Print status result with checkmark or X
 * @param success Success status
 * @param message Status message
 */
static void print_status(bool success, const char* message) {
    printf("%s %s\n", success ? "[✓]" : "[✗]", message);
}

// =============================================================================
// TEST FUNCTIONS
// =============================================================================

/**
 * @brief Test 1: Read device serial number
 * 
 * The ATECC608 contains a unique 9-byte serial number that cannot be changed.
 * This test reads and displays the serial number, which can be used for
 * device identification and tracking.
 * 
 * @return true if serial number read successfully, false otherwise
 */
static bool test_read_serial_number(void) {
    print_section_header("TEST 1: Read Serial Number");
    
    uint8_t serial_number[ATCA_SERIAL_NUM_SIZE];  // 9 bytes
    memset(serial_number, 0, sizeof(serial_number));
    
    printf("Reading device serial number...\n");
    
    ATCA_STATUS status = atcab_read_serial_number(serial_number);
    
    if (status != ATCA_SUCCESS) {
        print_status(false, "Failed to read serial number");
        printf("    Error code: 0x%02X\n", status);
        return false;
    }
    
    print_status(true, "Serial number read successfully");
    print_hex_buffer("    Serial", serial_number, ATCA_SERIAL_NUM_SIZE);
    
    // Parse serial number structure
    printf("    Breakdown:\n");
    printf("      Part 1: %02X %02X %02X %02X\n",
           serial_number[0], serial_number[1], serial_number[2], serial_number[3]);
    printf("      Part 2: %02X %02X %02X %02X %02X\n",
           serial_number[4], serial_number[5], serial_number[6], 
           serial_number[7], serial_number[8]);
    
    return true;
}

/**
 * @brief Test 2: Generate random number
 * 
 * The ATECC608 includes a hardware random number generator that produces
 * cryptographically secure random values. This test generates a 32-byte
 * random number and displays it.
 * 
 * @return true if random number generated successfully, false otherwise
 */
static bool test_generate_random_number(void) {
    print_section_header("TEST 2: Generate Random Number");
    
    uint8_t random_buffer[ATCA_RANDOM_BUFFER_SIZE];  // 32 bytes
    memset(random_buffer, 0, sizeof(random_buffer));
    
    printf("Generating 32-byte random number...\n");
    
    ATCA_STATUS status = atcab_random(random_buffer);
    
    if (status != ATCA_SUCCESS) {
        print_status(false, "Failed to generate random number");
        printf("    Error code: 0x%02X\n", status);
        return false;
    }
    
    print_status(true, "Random number generated successfully");
    print_hex_buffer("    Random", random_buffer, ATCA_RANDOM_BUFFER_SIZE);
    
    // Verify that we got actual random data (not all zeros)
    bool has_nonzero = false;
    for (size_t i = 0; i < ATCA_RANDOM_BUFFER_SIZE; i++) {
        if (random_buffer[i] != 0) {
            has_nonzero = true;
            break;
        }
    }
    
    if (has_nonzero) {
        printf("    ✓ Random data appears valid (contains non-zero bytes)\n");
    } else {
        printf("    ⚠ Warning: Random data is all zeros (unexpected)\n");
    }
    
    return true;
}

/**
 * @brief Test 3: Device information query
 * 
 * Reads the device revision information to verify communication and
 * display the chip model/version.
 * 
 * @return true if info read successfully, false otherwise
 */
static bool test_read_device_info(void) {
    print_section_header("TEST 3: Read Device Info");
    
    uint8_t revision[4];
    memset(revision, 0, sizeof(revision));
    
    printf("Reading device revision...\n");
    
    ATCA_STATUS status = atcab_info(revision);
    
    if (status != ATCA_SUCCESS) {
        print_status(false, "Failed to read device info");
        printf("    Error code: 0x%02X\n", status);
        return false;
    }
    
    print_status(true, "Device info read successfully");
    print_hex_buffer("    Revision", revision, 4);
    
    // Decode revision bytes
    printf("    Device type: ");
    if (revision[2] == 0x60) {
        printf("ATECC608");
        if (revision[3] == 0x01) {
            printf("A\n");
        } else if (revision[3] == 0x02) {
            printf("B\n");
        } else {
            printf(" (variant 0x%02X)\n", revision[3]);
        }
    } else {
        printf("Unknown (0x%02X%02X)\n", revision[2], revision[3]);
    }
    
    return true;
}

// =============================================================================
// MAIN PROGRAM
// =============================================================================

int main(void) {
    // Initialize standard I/O for USB serial
    stdio_init_all();
    sleep_ms(2000);  // Wait for USB serial to stabilize
    
    // Print application header
    printf("\n");
    printf("╔════════════════════════════════════════╗\n");
    printf("║  ATECC608 Functionality Test Suite    ║\n");
    printf("║  Serial Number & Random Number Gen    ║\n");
    printf("╚════════════════════════════════════════╝\n");
    printf("\n");
    
    // Initialize I2C hardware
    print_section_header("Hardware Initialization");
    printf("Configuring I2C interface...\n");
    i2c_init(I2C_CONTROLLER, I2C_FREQUENCY_HZ);
    gpio_set_function(I2C_SDA_PIN_NUM, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL_PIN_NUM, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SDA_PIN_NUM);
    gpio_pull_up(I2C_SCL_PIN_NUM);
    print_status(true, "I2C initialized");
    printf("    Bus: i2c0\n");
    printf("    Frequency: %d kHz\n", I2C_FREQUENCY_HZ / 1000);
    printf("    SDA: GP%d\n", I2C_SDA_PIN_NUM);
    printf("    SCL: GP%d\n", I2C_SCL_PIN_NUM);
    
    // Initialize CryptoAuthLib
    printf("\nInitializing CryptoAuthLib...\n");
    ATCA_STATUS init_status = atcab_init(&atecc608_interface_config);
    
    if (init_status != ATCA_SUCCESS) {
        print_status(false, "CryptoAuthLib initialization failed");
        printf("    Error code: 0x%02X\n", init_status);
        printf("\nTroubleshooting:\n");
        printf("  - Check I2C wiring (GP4=SDA, GP5=SCL)\n");
        printf("  - Verify 3.3V power and ground connections\n");
        printf("  - Ensure external pull-up resistors (2.2k-4.7k) on SDA/SCL\n");
        printf("  - Confirm ATECC608 device address is 0x60\n");
        return 1;
    }
    
    print_status(true, "CryptoAuthLib initialized successfully");
    
    // Run test suite
    bool test1_pass = test_read_device_info();
    bool test2_pass = test_read_serial_number();
    bool test3_pass = test_generate_random_number();
    
    // Print summary
    print_section_header("Test Results Summary");
    printf("Device Info:      %s\n", test1_pass ? "PASS ✓" : "FAIL ✗");
    printf("Serial Number:    %s\n", test2_pass ? "PASS ✓" : "FAIL ✗");
    printf("Random Number:    %s\n", test3_pass ? "PASS ✓" : "FAIL ✗");
    printf("\n");
    
    int total_tests = 3;
    int passed_tests = (test1_pass ? 1 : 0) + (test2_pass ? 1 : 0) + (test3_pass ? 1 : 0);
    
    printf("Overall: %d/%d tests passed\n", passed_tests, total_tests);
    
    if (passed_tests == total_tests) {
        printf("\n");
        printf("╔════════════════════════════════════════╗\n");
        printf("║          ALL TESTS PASSED ✓            ║\n");
        printf("║  ATECC608 is working correctly!        ║\n");
        printf("╚════════════════════════════════════════╝\n");
    } else {
        printf("\n");
        printf("╔════════════════════════════════════════╗\n");
        printf("║         SOME TESTS FAILED ✗            ║\n");
        printf("║  Check wiring and configuration        ║\n");
        printf("╚════════════════════════════════════════╝\n");
    }
    
    // Cleanup
    atcab_release();
    
    // Keep running
    while (true) {
        tight_loop_contents();
    }
    
    return 0;
}
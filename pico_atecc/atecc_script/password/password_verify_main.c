#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "cryptoauthlib.h"
#include "password_verify.h"

// Forward declarations (from password.c)
ATCA_STATUS password_init(void);
ATCA_STATUS password_hash(const char* password, uint8_t* hash);
ATCA_STATUS password_store(const char* password);
bool password_verify(const char* input);  // Modified signature

// I2C configuration
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
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0 && i < len - 1) printf("\n     ");
    }
    printf("\n");
}

int main(void) {
    stdio_init_all();
    sleep_ms(2000);
    
    printf("\n╔═══════════════════════════════════════╗\n");
    printf("║  Password Verification System        ║\n");
    printf("╚═══════════════════════════════════════╝\n");
    
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

    // Store password
    const char* password = "MySecretPass123!";
    printf("\nStoring password: %s\n", password);
    status = password_store(password);
    if (status != ATCA_SUCCESS) {
        printf("[-] Failed to store password: 0x%08X\n", status);
        return 1;
    }
    printf("[+] Password stored successfully\n");

    // Verification Tests
    printf("\n═══════════════════════════════════════\n");
    printf("  Password Verification Tests\n");
    printf("═══════════════════════════════════════\n");
    
    // Test 1: Correct password
    printf("\nTest 1: Login with correct password\n");
    const char* input1 = "MySecretPass123!";
    printf("Input: %s\n", input1);
    printf("Verifying... ");
    
    if (password_verify(input1)) {
        printf("[+] ACCESS GRANTED!\n");
    } else {
        printf("[-] ACCESS DENIED (ERROR - should pass!)\n");
    }
    
    // Test 2: Wrong password
    printf("\nTest 2: Login with wrong password\n");
    const char* input2 = "WrongPassword!";
    printf("Input: %s\n", input2);
    printf("Verifying... ");
    
    if (password_verify(input2)) {
        printf("[-] ACCESS GRANTED (ERROR - should fail!)\n");
    } else {
        printf("[+] ACCESS DENIED (correct!)\n");
    }
    
    
    // Simulate login attempts
    printf("\n═══════════════════════════════════════\n");
    printf("  Simulated Login Sequence\n");
    printf("═══════════════════════════════════════\n");
    
    const char* attempts[] = {
        "admin123",
        "password",
        "12345678",
        "MySecretPass123!",
        "test"
    };
    
    for (int i = 0; i < 5; i++) {
        printf("\nAttempt %d: %s\n", i + 1, attempts[i]);
        
        if (password_verify(attempts[i])) {
            printf("✅ Login successful!\n");
            printf("   Welcome to the system!\n");
            break;
        } else {
            printf("❌ Login failed\n");
            printf("   %d attempts remaining\n", 4 - i);
        }
    }
    
    // Summary
    printf("\n═══════════════════════════════════════\n");
    printf("  Summary\n");
    printf("═══════════════════════════════════════\n");
    
    printf("\n✅ Password System Complete!\n");
    printf("\n🔒 Security: Encrypted storage in Slot 13\n");
    printf("⏱️  Performance: Direct comparison from chip\n");
    printf("💾 Storage: Password encrypted with IO key\n");
    
    atcab_release();
    
    printf("\n✅ Demo complete!\n\n");
    
    while (true) {
        tight_loop_contents();
    }
    
    return 0;
}
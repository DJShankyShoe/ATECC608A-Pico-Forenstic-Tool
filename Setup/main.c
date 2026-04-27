#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "cryptoauthlib.h"
#include "cert_signing.h"

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
    
    printf("\n╔═══════════════════════════════════════════╗\n");
    printf("║  Self-Signed Certificate (ATECC608A)     ║\n");
    printf("╚═══════════════════════════════════════════╝\n");
    
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
    printf("[+] ATECC608A initialized\n");
    
    // Generate self-signed certificate using Slot 0
    printf("\n=== Generating Self-Signed Certificate ===\n");
    
    certificate_t cert;
    status = cert_generate_self_signed(
        0,                    // Slot 0
        "PICO_TEAMIS18",     // Common Name
        "SIT",               // Organization
        "SG",                // Country
        &cert
    );
    
    if (status != ATCA_SUCCESS) {
        printf("[-] Certificate generation failed: 0x%08X\n", status);
        atcab_release();
        return 1;
    }
    
    printf("[+] Certificate generated successfully!\n");
    printf("    Size: %zu bytes\n", cert.der_length);
    
    // Print certificate in PEM format
    printf("\n=== Self-Signed Certificate (PEM) ===\n");
    cert_print_pem(&cert);
    
    // Print certificate in hex format (for verification)
    printf("\n=== Self-Signed Certificate (DER Hex) ===\n");
    cert_print_hex(&cert);
    
    // Verification info
    printf("\n=== Verification ===\n");
    printf("You can verify this certificate using OpenSSL:\n");
    printf("1. Save the PEM output above to 'cert.pem'\n");
    printf("2. Run: openssl x509 -in cert.pem -text -noout\n");
    printf("3. Verify signature: openssl verify -CAfile cert.pem cert.pem\n");
    
    // When done, free the certificate
    cert_free(&cert);
    printf("\n[+] Certificate freed\n");
    
    atcab_release();
    
    printf("\n[+] Demo complete!\n\n");
    
    while (true) {
        tight_loop_contents();
    }
    
    return 0;
}
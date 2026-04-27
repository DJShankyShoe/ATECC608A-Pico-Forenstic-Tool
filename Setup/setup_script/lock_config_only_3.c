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
        .address    = 0xC0 >> 1,   // 7-bit (0x60)
        .bus        = 0,
        .baud       = I2C_FREQUENCY
    },
    .wake_delay = 1500,
    .rx_retries = 1,
    .cfg_data   = NULL
};

static void print_hex_block(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 8 == 0) printf(" ");
    }
    if (len % 16) printf("\n");
}

static int read_lock_bytes(uint8_t *lock_value, uint8_t *lock_config) {
    uint8_t cfg[128];
    ATCA_STATUS s = atcab_read_config_zone(cfg);
    if (s != ATCA_SUCCESS) {
        printf("❌ atcab_read_config_zone failed: 0x%02X\n", s);
        return -1;
    }
    *lock_value  = cfg[86]; // Data zone lock byte
    *lock_config = cfg[87]; // Config zone lock byte
    return 0;
}

static void print_lock_state(const char *label) {
    uint8_t lv=0, lc=0;
    if (read_lock_bytes(&lv, &lc) == 0) {
        printf("%s\n  DataLock  (byte 86): 0x%02X %s\n  ConfigLock(byte 87): 0x%02X %s\n",
               label,
               lv, (lv == 0x55 ? "(UNLOCKED)" : (lv == 0x00 ? "(LOCKED)" : "(UNKNOWN)")),
               lc, (lc == 0x55 ? "(UNLOCKED)" : (lc == 0x00 ? "(LOCKED)" : "(UNKNOWN)")));
    }
}

int main(void) {
    stdio_init_all();
    sleep_ms(1200);

    printf("\n");
    printf("╔══════════════════════════════════════════╗\n");
    printf("║  ATECC608 Config Lock Tool (Config ONLY) ║\n");
    printf("╚══════════════════════════════════════════╝\n");

    // I2C init
    i2c_init(I2C_CONTROLLER, I2C_FREQUENCY);
    gpio_set_function(I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SDA_PIN);
    gpio_pull_up(I2C_SCL_PIN);

    ATCA_STATUS s = atcab_init(&atecc_cfg);
    if (s != ATCA_SUCCESS) {
        printf("❌ atcab_init failed: 0x%02X\n", s);
        return 1;
    }

    // Show current state
    print_lock_state("Current lock state:");

    // Ensure config is unlocked
    uint8_t lv=0, lc=0;
    if (read_lock_bytes(&lv, &lc) != 0) { atcab_release(); return 1; }
    if (lc != 0x55) {
        printf("⚠️  Config zone is already LOCKED (0x%02X). Nothing to do.\n", lc);
        atcab_release();
        return 0;
    }

#ifndef NO_CONFIRM
    // Require explicit "LOCK" before proceeding
    printf("\nType \"LOCK\" then press ENTER to permanently lock the CONFIG zone (NOT data): ");
    char buf[16] = {0};
    int idx = 0;
    while (1) {
        int ch = getchar_timeout_us(5 * 1000 * 1000); // 5s
        if (ch == PICO_ERROR_TIMEOUT) {
            printf("\n⏳ Still waiting... type LOCK and press ENTER: ");
            continue;
        }
        if (ch == '\r' || ch == '\n') break;
        if (idx < (int)sizeof(buf)-1) buf[idx++] = (char)ch;
    }
    if (strcmp(buf, "LOCK") != 0) {
        printf("Aborted. (You typed: \"%s\")\n", buf);
        atcab_release();
        return 0;
    }
#endif

    printf("\nLocking CONFIG zone...\n");
    s = atcab_lock_config_zone();
    if (s != ATCA_SUCCESS) {
        printf("❌ atcab_lock_config_zone failed: 0x%02X\n", s);
        atcab_release();
        return 1;
    }

    // Read back and show
    print_lock_state("Post-lock state:");

    // Sanity: Data zone remains untouched
    if (read_lock_bytes(&lv, &lc) == 0) {
        if (lv != 0x55) {
            printf("❗ Warning: DataLock changed (expected 0x55, got 0x%02X). Data was not supposed to be locked.\n", lv);
        } else {
            printf("✅ Data zone remains UNLOCKED (0x55). Only CONFIG was locked.\n");
        }
    }

    atcab_release();
    printf("Done.\n");
    while (true) { tight_loop_contents(); }
    return 0;
}

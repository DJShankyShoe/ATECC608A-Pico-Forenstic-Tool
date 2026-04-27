/**
 * Layout (does NOT lock any zone):
 *  - Slot 0: ECC (TLS signing)  — GenKey + PrivWrite(enc), Sign, no ECDH
 *  - Slot 1: ECC (sign-only)    — GenKey only, Sign, no ECDH
 *  - Slot 2: ECC (sign+ECDH)    — GenKey + PrivWrite(enc), Sign+ECDH
 *  - Slot 3: ECC (ECDH+writeNext) — GenKey only, Sign+ECDH(+write-next)
 *  - Slot 4: Data (I/O key, DEV) — clear R/W
 *  - Slot 5: Data (pwd verifier, DEV) — clear R/W
 *  - Slot 6: Data (AAD/meta, DEV) — clear R/W
 *  - Slot 7–8: Data (scratch, DEV) — clear R/W
 *  - Slot 9: AES (prod)          — EncryptedWrite only (WK=4)
 *  - Slot 10: AES (prod)         — EncryptedWrite only (WK=4)
 *  - Slot 11: AES (DEV)          — Plain write allowed (still not readable)
 *  - Slot 12: Data (scratch, DEV) — clear R/W
 *  - Slot 13–15: Secret Data     — NoRead, EncryptedWrite only (WK=4)
 */

#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "cryptoauthlib.h"

// =============================================================================
// I2C CONFIGURATION
// =============================================================================

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

// SlotConfig helper macros
#define SLOTCONFIG_READKEY(x)       ((x) & 0x0F)            // for Data/AES OR ECC perms nibble
#define SLOTCONFIG_NOMAC            (1 << 4)
#define SLOTCONFIG_LIMITED_USE      (1 << 5)
#define SLOTCONFIG_ENCRYPT_READ     (1 << 6)
#define SLOTCONFIG_IS_SECRET        (1 << 7)
#define SLOTCONFIG_WRITEKEY(x)      (((x) & 0x0F) << 8)
#define SLOTCONFIG_WRITECONFIG(x)   (((x) & 0x0F) << 12)

// KeyConfig helper macros
#define KEYCONFIG_PRIVATE           (1 << 0)
#define KEYCONFIG_PUBINFO           (1 << 1)
#define KEYCONFIG_KEYTYPE(x)        (((x) & 0x07) << 2)
#define KEYCONFIG_LOCKABLE          (1 << 5)
#define KEYCONFIG_REQRANDOM         (1 << 6)
#define KEYCONFIG_REQAUTH           (1 << 7)
#define KEYCONFIG_AUTHKEY(x)        (((x) & 0x0F) << 8)

// Key type values
#define KEYTYPE_ECC_P256            4
#define KEYTYPE_AES                 6
#define KEYTYPE_DATA                7

// WriteConfig values (nibbles)
#define WRITECONFIG_DATA_ALWAYS           0x0  // Always write (DEV)
#define WRITECONFIG_ECC_GENKEY_ONLY       0x2  // ECC: GenKey only
#define WRITECONFIG_DATA_ENCWRITE_ONLY    0x4  // Data/AES: EncryptedWrite only (uses WriteKey)
#define WRITECONFIG_ECC_GENKEY_PRIVWRITE  0x6  // ECC: GenKey + PrivWrite(enc)

// ECC perms (low nibble for ECC private)
#define ECCPERM_TLS_SIGN_ONLY             0x3  // ExtSign=1, IntSign=1, ECDH=0
#define ECCPERM_SIGN_AND_ECDH             0x7  // ExtSign=1, IntSign=1, ECDH=1
#define ECCPERM_SIGN_ECDH_WRNEXT          0xF  // ExtSign=1, IntSign=1, ECDH=1, write-next=1

// ReadKey values (for Data/AES)
#define READKEY_NEVER               0xF  // Never readable (private/AES/secret data)
#define READKEY_CLEAR               0x0  // Always readable (DEV)

// =============================================================================
// SLOT CONFIGURATIONS (According to specification)
// =============================================================================

// SLOT 0: TLS Server Private Key (ECC P-256), Sign only, GenKey + PrivWrite(enc), WK=4
#define SLOT0_SLOTCONFIG ( \
    SLOTCONFIG_READKEY(ECCPERM_TLS_SIGN_ONLY) | \
    SLOTCONFIG_IS_SECRET | \
    SLOTCONFIG_WRITEKEY(4) | \
    SLOTCONFIG_WRITECONFIG(WRITECONFIG_ECC_GENKEY_PRIVWRITE) \
)
#define SLOT0_KEYCONFIG ( \
    KEYCONFIG_PRIVATE | KEYCONFIG_PUBINFO | KEYCONFIG_KEYTYPE(KEYTYPE_ECC_P256) \
)

// SLOT 1: ECC private (sign-only), GenKey only (no PrivWrite), NoRead
#define SLOT1_SLOTCONFIG ( \
    SLOTCONFIG_READKEY(ECCPERM_TLS_SIGN_ONLY) | \
    SLOTCONFIG_IS_SECRET | \
    SLOTCONFIG_WRITEKEY(0) | \
    SLOTCONFIG_WRITECONFIG(WRITECONFIG_ECC_GENKEY_ONLY) \
)
#define SLOT1_KEYCONFIG ( \
    KEYCONFIG_PRIVATE | KEYCONFIG_PUBINFO | KEYCONFIG_KEYTYPE(KEYTYPE_ECC_P256) \
)

// SLOT 2: ECC private (sign + ECDH), GenKey + PrivWrite(enc), WK=4
#define SLOT2_SLOTCONFIG ( \
    SLOTCONFIG_READKEY(ECCPERM_SIGN_AND_ECDH) | \
    SLOTCONFIG_IS_SECRET | \
    SLOTCONFIG_WRITEKEY(4) | \
    SLOTCONFIG_WRITECONFIG(WRITECONFIG_ECC_GENKEY_PRIVWRITE) \
)
#define SLOT2_KEYCONFIG ( \
    KEYCONFIG_PRIVATE | KEYCONFIG_PUBINFO | KEYCONFIG_KEYTYPE(KEYTYPE_ECC_P256) \
)

// SLOT 3: ECC private (sign + ECDH + write-next), GenKey only
#define SLOT3_SLOTCONFIG ( \
    SLOTCONFIG_READKEY(ECCPERM_SIGN_ECDH_WRNEXT) | \
    SLOTCONFIG_IS_SECRET | \
    SLOTCONFIG_WRITEKEY(0) | \
    SLOTCONFIG_WRITECONFIG(WRITECONFIG_ECC_GENKEY_ONLY) \
)
#define SLOT3_KEYCONFIG ( \
    KEYCONFIG_PRIVATE | KEYCONFIG_PUBINFO | KEYCONFIG_KEYTYPE(KEYTYPE_ECC_P256) \
)

// SLOT 4/5/6/7/8/12: DEV clear data
#define SLOT_DEV_CLEAR_SLOTCONFIG ( \
    SLOTCONFIG_READKEY(READKEY_CLEAR) | \
    SLOTCONFIG_WRITEKEY(0) | \
    SLOTCONFIG_WRITECONFIG(WRITECONFIG_DATA_ALWAYS) \
)
#define SLOT_DEV_CLEAR_KEYCONFIG ( KEYCONFIG_KEYTYPE(KEYTYPE_DATA) )

// SLOT 9 / 10: AES (prod) — EncryptedWrite only, WK=4, NoRead
#define SLOT_AES_PROD_SLOTCONFIG ( \
    SLOTCONFIG_READKEY(READKEY_NEVER) | \
    SLOTCONFIG_IS_SECRET | \
    SLOTCONFIG_WRITEKEY(4) | \
    SLOTCONFIG_WRITECONFIG(WRITECONFIG_DATA_ENCWRITE_ONLY) \
)
#define SLOT_AES_KEYCONFIG ( KEYCONFIG_KEYTYPE(KEYTYPE_AES) )

// SLOT 11: AES (DEV) — Plain write allowed (not readable)
#define SLOT_AES_DEV_SLOTCONFIG ( \
    SLOTCONFIG_READKEY(READKEY_NEVER) | \
    SLOTCONFIG_IS_SECRET | \
    SLOTCONFIG_WRITEKEY(0) | \
    SLOTCONFIG_WRITECONFIG(WRITECONFIG_DATA_ALWAYS) \
)

// SLOT 13/14/15: Secret Data — NoRead, EncryptedWrite only (WK=4)
#define SLOT_SECRET_DATA_SLOTCONFIG ( \
    SLOTCONFIG_READKEY(READKEY_NEVER) | \
    SLOTCONFIG_IS_SECRET | \
    SLOTCONFIG_WRITEKEY(4) | \
    SLOTCONFIG_WRITECONFIG(WRITECONFIG_DATA_ENCWRITE_ONLY) \
)
#define SLOT_SECRET_DATA_KEYCONFIG ( KEYCONFIG_KEYTYPE(KEYTYPE_DATA) )

// =============================================================================
// CONFIGURATION DATA STRUCTURE
// =============================================================================

typedef struct {
    uint16_t slot_config[16];  // Offset 20-51 in config zone
    uint16_t key_config[16];   // Offset 96-127 in config zone
} ateccx08_slot_config_t;

static const ateccx08_slot_config_t dev_config = {
    .slot_config = {
        /* 0  */ SLOT0_SLOTCONFIG,
        /* 1  */ SLOT1_SLOTCONFIG,
        /* 2  */ SLOT2_SLOTCONFIG,
        /* 3  */ SLOT3_SLOTCONFIG,
        /* 4  */ SLOT_DEV_CLEAR_SLOTCONFIG,
        /* 5  */ SLOT_DEV_CLEAR_SLOTCONFIG,
        /* 6  */ SLOT_DEV_CLEAR_SLOTCONFIG,
        /* 7  */ SLOT_DEV_CLEAR_SLOTCONFIG,
        /* 8  */ SLOT_DEV_CLEAR_SLOTCONFIG,
        /* 9  */ SLOT_AES_PROD_SLOTCONFIG,
        /* 10 */ SLOT_AES_PROD_SLOTCONFIG,
        /* 11 */ SLOT_AES_DEV_SLOTCONFIG,
        /* 12 */ SLOT_DEV_CLEAR_SLOTCONFIG,
        /* 13 */ SLOT_SECRET_DATA_SLOTCONFIG,
        /* 14 */ SLOT_SECRET_DATA_SLOTCONFIG,
        /* 15 */ SLOT_SECRET_DATA_SLOTCONFIG
    },
    .key_config = {
        /* 0  */ SLOT0_KEYCONFIG,
        /* 1  */ SLOT1_KEYCONFIG,
        /* 2  */ SLOT2_KEYCONFIG,
        /* 3  */ SLOT3_KEYCONFIG,
        /* 4  */ SLOT_DEV_CLEAR_KEYCONFIG,
        /* 5  */ SLOT_DEV_CLEAR_KEYCONFIG,
        /* 6  */ SLOT_DEV_CLEAR_KEYCONFIG,
        /* 7  */ SLOT_DEV_CLEAR_KEYCONFIG,
        /* 8  */ SLOT_DEV_CLEAR_KEYCONFIG,
        /* 9  */ SLOT_AES_KEYCONFIG,
        /* 10 */ SLOT_AES_KEYCONFIG,
        /* 11 */ SLOT_AES_KEYCONFIG,
        /* 12 */ SLOT_DEV_CLEAR_KEYCONFIG,
        /* 13 */ SLOT_SECRET_DATA_KEYCONFIG,
        /* 14 */ SLOT_SECRET_DATA_KEYCONFIG,
        /* 15 */ SLOT_SECRET_DATA_KEYCONFIG
    }
};

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

static void print_header(const char* title) {
    printf("\n");
    printf("========================================\n");
    printf("  %s\n", title);
    printf("========================================\n");
}

static void print_hex_block(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 8 == 0) printf(" ");
    }
    if (len % 16 != 0) printf("\n");
}

static void print_slot_config_decoded(uint8_t slot, uint16_t slotconfig, uint16_t keyconfig) {
    printf("\n--- Slot %2d Configuration ---\n", slot);
    printf("SlotConfig: 0x%04X\n", slotconfig);
    printf("  LowNibble: 0x%X %s\n",
           slotconfig & 0x0F,
           (keyconfig & KEYCONFIG_PRIVATE) ? "(ECC perms)" : "(ReadKey)");
    printf("  NoMac:       %d\n", (slotconfig >> 4) & 1);
    printf("  LimitedUse:  %d\n", (slotconfig >> 5) & 1);
    printf("  EncryptRead: %d\n", (slotconfig >> 6) & 1);
    printf("  IsSecret:    %d %s\n",
           (slotconfig >> 7) & 1,
           (slotconfig >> 7) & 1 ? "(Secret)" : "(Clear)");
    printf("  WriteKey:    0x%X (Slot %d)\n",
           (slotconfig >> 8) & 0x0F,
           (slotconfig >> 8) & 0x0F);
    printf("  WriteConfig: 0x%X\n", (slotconfig >> 12) & 0x0F);

    printf("KeyConfig: 0x%04X\n", keyconfig);
    printf("  Private:     %d %s\n",
           keyconfig & 1,
           keyconfig & 1 ? "(Private ECC)" : "(Public/Data)");
    printf("  PubInfo:     %d\n", (keyconfig >> 1) & 1);

    uint8_t keytype = (keyconfig >> 2) & 0x07;
    const char* keytype_str = "Unknown";
    if (keytype == 4) keytype_str = "ECC P-256";
    else if (keytype == 6) keytype_str = "AES";
    else if (keytype == 7) keytype_str = "Data";
    printf("  KeyType:     %d (%s)\n", keytype, keytype_str);

    printf("  Lockable:    %d\n", (keyconfig >> 5) & 1);
    printf("  ReqRandom:   %d\n", (keyconfig >> 6) & 1);
    printf("  ReqAuth:     %d\n", (keyconfig >> 7) & 1);
    printf("  AuthKey:     0x%X\n", (keyconfig >> 8) & 0x0F);
}

// =============================================================================
// CONFIGURATION FUNCTIONS
// =============================================================================

static bool read_current_config(uint8_t* config_zone) {
    printf("\nReading current configuration zone...\n");
    ATCA_STATUS status = atcab_read_config_zone(config_zone);

    if (status != ATCA_SUCCESS) {
        printf("❌ Failed to read config zone (error 0x%02X)\n", status);
        return false;
    }

    printf("✅ Config zone read successfully\n");
    return true;
}

static void show_config_comparison(const uint8_t* old_config, const uint8_t* new_config) {
    print_header("Configuration Comparison");

    printf("\nSlotConfig Changes (bytes 20-51):\n");
    for (int slot = 0; slot < 16; slot++) {
        int offset = 20 + (slot * 2);
        uint16_t old_sc = old_config[offset] | (old_config[offset + 1] << 8);
        uint16_t new_sc = new_config[offset] | (new_config[offset + 1] << 8);

        if (old_sc != new_sc) {
            printf("  Slot %2d: 0x%04X → 0x%04X %s\n",
                   slot, old_sc, new_sc, "✎ CHANGED");
        }
    }

    printf("\nKeyConfig Changes (bytes 96-127):\n");
    for (int slot = 0; slot < 16; slot++) {
        int offset = 96 + (slot * 2);
        uint16_t old_kc = old_config[offset] | (old_config[offset + 1] << 8);
        uint16_t new_kc = new_config[offset] | (new_config[offset + 1] << 8);

        if (old_kc != new_kc) {
            printf("  Slot %2d: 0x%04X → 0x%04X %s\n",
                   slot, old_kc, new_kc, "✎ CHANGED");
        }
    }
}

static bool write_new_config(uint8_t* config_zone) {
    print_header("Writing New Configuration");

    printf("\n⚠️  IMPORTANT: Config zone must be UNLOCKED (LockConfig=0x55)!\n");
    printf("⚠️  This tool will NOT change lock bytes. It does NOT lock the device.\n");
    printf("\nStarting configuration write in 3 seconds...\n");

    for (int i = 3; i > 0; i--) { printf("%d... ", i); sleep_ms(1000); }
    printf("\n\n");

    // Write SlotConfig section (bytes 20-51)
    printf("Writing SlotConfig (bytes 20-51)...\n");
    for (int block = 0; block < 8; block++) {
        int offset = 20 + (block * 4);
        ATCA_STATUS status = atcab_write_bytes_zone(
            ATCA_ZONE_CONFIG, 0, offset, &config_zone[offset], 4
        );
        if (status != ATCA_SUCCESS) {
            printf("❌ Failed to write SlotConfig block %d (error 0x%02X)\n", block, status);
            return false;
        }
        printf("  ✅ Block %d written (offset %d)\n", block, offset);
    }

    // Write KeyConfig section (bytes 96-127)
    printf("\nWriting KeyConfig (bytes 96-127)...\n");
    for (int block = 0; block < 8; block++) {
        int offset = 96 + (block * 4);
        ATCA_STATUS status = atcab_write_bytes_zone(
            ATCA_ZONE_CONFIG, 0, offset, &config_zone[offset], 4
        );
        if (status != ATCA_SUCCESS) {
            printf("❌ Failed to write KeyConfig block %d (error 0x%02X)\n", block, status);
            return false;
        }
        printf("  ✅ Block %d written (offset %d)\n", block, offset);
    }

    printf("\n✅ Configuration write complete!\n");
    return true;
}

static void verify_written_config(void) {
    print_header("Verifying Written Configuration");

    uint8_t verify_config[128];
    ATCA_STATUS status = atcab_read_config_zone(verify_config);

    if (status != ATCA_SUCCESS) {
        printf("❌ Failed to verify (couldn't read config)\n");
        return;
    }

    printf("\nKey slots configuration:\n");
    for (int slot = 0; slot < 16; slot++) {
        int sc_offset = 20 + (slot * 2);
        int kc_offset = 96 + (slot * 2);

        uint16_t slotconfig = verify_config[sc_offset] | (verify_config[sc_offset + 1] << 8);
        uint16_t keyconfig  = verify_config[kc_offset] | (verify_config[kc_offset + 1] << 8);

        // Show all the interesting ones
        if (slot == 0 || slot == 1 || slot == 2 || slot == 3 ||
            slot == 4 || slot == 5 || slot == 6 ||
            slot == 9 || slot == 10 || slot == 11 ||
            slot == 13 || slot == 14 || slot == 15) {
            print_slot_config_decoded(slot, slotconfig, keyconfig);
        }
    }

    printf("\n✅ Verification complete\n");
}

// =============================================================================
// MAIN PROGRAM
// =============================================================================

int main(void) {
    stdio_init_all();
    sleep_ms(2000);

    // Header
    printf("\n");
    printf("╔═══════════════════════════════════════╗\n");
    printf("║  ATECC608 Configuration Writer        ║\n");
    printf("║  DEV MODE - UNLOCKED                  ║\n");
    printf("╚═══════════════════════════════════════╝\n");

    // I2C init
    print_header("Hardware Initialization");
    i2c_init(I2C_CONTROLLER, I2C_FREQUENCY);
    gpio_set_function(I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SDA_PIN);
    gpio_pull_up(I2C_SCL_PIN);
    printf("✅ I2C initialized\n");

    // CryptoAuthLib init
    printf("Initializing CryptoAuthLib...\n");
    ATCA_STATUS status = atcab_init(&atecc_cfg);
    if (status != ATCA_SUCCESS) {
        printf("❌ CryptoAuthLib init failed (error 0x%02X)\n", status);
        return 1;
    }
    printf("✅ CryptoAuthLib initialized\n");

    // Read current config
    uint8_t old_config[128];
    if (!read_current_config(old_config)) { atcab_release(); return 1; }

    printf("\nCurrent configuration:\n");
    print_hex_block(old_config, 128);

    // Lock bytes
    printf("\nLock Status:\n");
    printf("  ConfigLock (byte 87): 0x%02X %s\n",
           old_config[87], old_config[87] == 0x55 ? "(UNLOCKED ✅)" : "(LOCKED ❌)");
    printf("  DataLock   (byte 86): 0x%02X %s\n",
           old_config[86], old_config[86] == 0x55 ? "(UNLOCKED ✅)" : "(LOCKED ❌)");

    if (old_config[87] != 0x55) {
        printf("\n❌ ERROR: Config zone is LOCKED! Cannot modify configuration.\n");
        atcab_release();
        return 1;
    }

    // Build new config (start from old, then patch tables)
    uint8_t new_config[128];
    memcpy(new_config, old_config, 128);

    // Update SlotConfig (bytes 20-51)
    for (int slot = 0; slot < 16; slot++) {
        int offset = 20 + (slot * 2);
        uint16_t sc = dev_config.slot_config[slot];
        new_config[offset]     = sc & 0xFF;
        new_config[offset + 1] = (sc >> 8) & 0xFF;
    }

    // Update KeyConfig (bytes 96-127)
    for (int slot = 0; slot < 16; slot++) {
        int offset = 96 + (slot * 2);
        uint16_t kc = dev_config.key_config[slot];
        new_config[offset]     = kc & 0xFF;
        new_config[offset + 1] = (kc >> 8) & 0xFF;
    }

    // Show comparison
    show_config_comparison(old_config, new_config);

    printf("\n");
    printf("═══════════════════════════════════════\n");
    printf("  Ready to write configuration\n");
    printf("═══════════════════════════════════════\n");
    printf("\nThis will configure:\n");
    printf("  • Slot 0: ECC TLS signing (GenKey+PrivWrite(enc), WK=4)\n");
    printf("  • Slot 1: ECC sign-only (GenKey only)\n");
    printf("  • Slot 2: ECC sign+ECDH (GenKey+PrivWrite(enc), WK=4)\n");
    printf("  • Slot 3: ECC sign+ECDH+write-next (GenKey only)\n");
    printf("  • Slot 4/5/6/7/8/12: Data (DEV clear R/W)\n");
    printf("  • Slot 9: AES (prod, EncWrite only, WK=4)\n");
    printf("  • Slot 10: AES (prod, EncWrite only, WK=4)\n");
    printf("  • Slot 11: AES (DEV, plain write allowed)\n");
    printf("  • Slot 13/14/15: Secret Data (NoRead, EncWrite only, WK=4)\n");
    printf("\n⚠️  Config/Data zones will remain UNLOCKED (bytes 87/86 stay 0x55)\n");
    printf("\nPress ENTER to continue, or Ctrl+C to cancel...");
    getchar();

    // Write configuration
    if (!write_new_config(new_config)) { atcab_release(); return 1; }

    // Verify
    verify_written_config();

    // Summary
    print_header("Summary");
    printf("\n✅ Configuration successfully written (device remains UNLOCKED).\n");
    printf("\nNext steps:\n");
    printf("1) Put your I/O key into Slot 4 (DEV clear) so PrivWrite/EncWrite can use WK=4.\n");
    printf("2) GenKey: slot0/slot2 (and slot1/slot3 if you want ECC there too).\n");
    printf("3) For AES in slots 9/10: use encrypted writes; slot 11 allows plain writes in DEV.\n");
    printf("4) When ready for PROD, tighten Slot 4 and lock zones.\n");

    atcab_release();
    while (true) { tight_loop_contents(); }
    return 0;
}

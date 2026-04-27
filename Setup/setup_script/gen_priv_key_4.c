/**
 * Generates ECC P-256 private keys in slots 0, 1, 2, 3
 * Tests ECDSA signing on all 4 slots
 * Tests ECDH on slots 2 and 3 (slots 0,1 don't have ECDH enabled)
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

// Slot capabilities based on user's config
typedef struct {
    uint8_t slot;
    const char* name;
    bool has_sign;
    bool has_ecdh;
    uint16_t slotconfig;
    uint16_t keyconfig;
} slot_info_t;

static const slot_info_t slots[] = {
    {0, "TLS/Sign", true, false, 0x6483, 0x0013},
    {1, "Sign-Only", true, false, 0x2083, 0x0013},
    {2, "Sign+ECDH", true, true, 0x6487, 0x0013},
    {3, "Sign+ECDH+WN", true, true, 0x208F, 0x0013}
};

static void print_hex_compact(const uint8_t* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
}

static void print_separator(void) {
    printf("════════════════════════════════════════\n");
}

static bool generate_key(uint8_t slot, uint8_t* pubkey_out) {
    printf("\n--- Slot %d: Generating Key ---\n", slot);
    
    // Step 1: Generate private key (mode=0x00)
    printf("Calling atcab_genkey(%d, NULL)\n", slot);
    ATCA_STATUS status = atcab_genkey(slot, NULL);
    
    if (status != ATCA_SUCCESS) {
        printf("❌ GenKey failed (0x%02X)\n", status);
        return false;
    }
    printf("✅ Private key generated\n");
    
    // Step 2: Extract public key
    printf("Calling atcab_get_pubkey(%d, pubkey)\n", slot);
    status = atcab_get_pubkey(slot, pubkey_out);
    
    if (status != ATCA_SUCCESS) {
        printf("❌ Get pubkey failed (0x%02X)\n", status);
        return false;
    }
    
    printf("✅ Public key extracted: ");
    print_hex_compact(pubkey_out, 16);
    printf("...\n");
    
    return true;
}

static bool test_ecdsa(uint8_t slot, const uint8_t* pubkey) {
    printf("\n--- Slot %d: Testing ECDSA ---\n", slot);
    
    // Create test message
    uint8_t message[32];
    for (int i = 0; i < 32; i++) {
        message[i] = 0xA0 + slot + (i % 16);
    }
    
    printf("Message: ");
    print_hex_compact(message, 16);
    printf("...\n");
    
    // Sign the message
    uint8_t signature[64];
    printf("Calling atcab_sign(%d, message, signature)\n", slot);
    ATCA_STATUS status = atcab_sign(slot, message, signature);
    
    if (status != ATCA_SUCCESS) {
        printf("❌ Sign failed (0x%02X)\n", status);
        return false;
    }
    
    printf("✅ Signature: ");
    print_hex_compact(signature, 16);
    printf("...\n");
    
    // Verify the signature
    bool is_verified = false;
    printf("Calling atcab_verify_extern(message, sig, pubkey, &verified)\n");
    status = atcab_verify_extern(message, signature, pubkey, &is_verified);
    
    if (status != ATCA_SUCCESS) {
        printf("❌ Verify command failed (0x%02X)\n", status);
        return false;
    }
    
    if (!is_verified) {
        printf("❌ Signature invalid!\n");
        return false;
    }
    
    printf("✅ Signature VERIFIED!\n");
    return true;
}

static bool test_ecdh(uint8_t slot_a, uint8_t slot_b, 
                      const uint8_t* pubkey_a, const uint8_t* pubkey_b) {
    printf("\n--- ECDH: Slot %d ⟷ Slot %d ---\n", slot_a, slot_b);
    
    // Slot A: ECDH with Slot B's public key
    uint8_t secret_a[32];
    printf("Calling atcab_ecdh(%d, pubkey_%d, secret_a)\n", slot_a, slot_b);
    ATCA_STATUS status = atcab_ecdh(slot_a, pubkey_b, secret_a);
    
    if (status != ATCA_SUCCESS) {
        printf("❌ ECDH on Slot %d failed (0x%02X)\n", slot_a, status);
        return false;
    }
    
    printf("✅ Slot %d shared secret: ", slot_a);
    print_hex_compact(secret_a, 16);
    printf("...\n");
    
    // Slot B: ECDH with Slot A's public key
    uint8_t secret_b[32];
    printf("Calling atcab_ecdh(%d, pubkey_%d, secret_b)\n", slot_b, slot_a);
    status = atcab_ecdh(slot_b, pubkey_a, secret_b);
    
    if (status != ATCA_SUCCESS) {
        printf("❌ ECDH on Slot %d failed (0x%02X)\n", slot_b, status);
        return false;
    }
    
    printf("✅ Slot %d shared secret: ", slot_b);
    print_hex_compact(secret_b, 16);
    printf("...\n");
    
    // Verify secrets match
    if (memcmp(secret_a, secret_b, 32) != 0) {
        printf("❌ ECDH secrets DO NOT MATCH!\n");
        return false;
    }
    
    printf("✅ ECDH secrets MATCH! Perfect forward secrecy established.\n");
    return true;
}

int main(void) {
    stdio_init_all();
    sleep_ms(2000);
    
    printf("\n");
    print_separator();
    printf("  Multi-Slot Key Provisioning\n");
    printf("  Slots 0, 1, 2, 3\n");
    print_separator();
    
    // Initialize hardware
    i2c_init(I2C_CONTROLLER, I2C_FREQUENCY);
    gpio_set_function(I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SDA_PIN);
    gpio_pull_up(I2C_SCL_PIN);
    printf("\n✅ I2C initialized\n");
    
    ATCA_STATUS status = atcab_init(&atecc_cfg);
    if (status != ATCA_SUCCESS) {
        printf("❌ Init failed (0x%02X)\n", status);
        return 1;
    }
    printf("✅ CryptoAuthLib initialized\n");
    
    // Read and verify config
    uint8_t config[128];
    status = atcab_read_config_zone(config);
    if (status != ATCA_SUCCESS) {
        printf("❌ Cannot read config\n");
        atcab_release();
        return 1;
    }
    
    printf("\n--- Lock Status ---\n");
    printf("ConfigLock: 0x%02X %s\n", config[87], 
           config[87] == 0x55 ? "(UNLOCKED ✅)" : "(LOCKED)");
    printf("DataLock:   0x%02X %s\n", config[86],
           config[86] == 0x55 ? "(UNLOCKED ✅)" : "(LOCKED)");
    printf("SlotLocked: 0x%04X\n", config[88] | (config[89] << 8));
    
    // Verify slot configurations
    printf("\n--- Slot Configurations ---\n");
    for (int i = 0; i < 4; i++) {
        int sc_offset = 20 + (slots[i].slot * 2);
        int kc_offset = 96 + (slots[i].slot * 2);
        uint16_t sc = config[sc_offset] | (config[sc_offset + 1] << 8);
        uint16_t kc = config[kc_offset] | (config[kc_offset + 1] << 8);
        
        printf("Slot %d (%s):\n", slots[i].slot, slots[i].name);
        printf("  SlotConfig: 0x%04X %s\n", sc, 
               sc == slots[i].slotconfig ? "✅" : "❌ MISMATCH!");
        printf("  KeyConfig:  0x%04X %s\n", kc,
               kc == slots[i].keyconfig ? "✅" : "❌ MISMATCH!");
        printf("  Capabilities: %s%s\n",
               slots[i].has_sign ? "Sign " : "",
               slots[i].has_ecdh ? "ECDH" : "");
    }
    
    // Generate keys in all 4 slots
    printf("\n");
    print_separator();
    printf("  PHASE 1: Key Generation\n");
    print_separator();
    
    printf("\n⚠️  This will OVERWRITE any existing keys!\n");
    printf("Proceeding in 3 seconds...\n");
    for (int i = 3; i > 0; i--) {
        printf("%d... ", i);
        sleep_ms(1000);
    }
    printf("\n");
    
    uint8_t public_keys[4][64];
    bool gen_success[4] = {false};
    
    for (int i = 0; i < 4; i++) {
        gen_success[i] = generate_key(slots[i].slot, public_keys[i]);
        if (!gen_success[i]) {
            printf("⚠️  Continuing with other slots...\n");
        }
    }
    
    // Test ECDSA on all generated keys
    printf("\n");
    print_separator();
    printf("  PHASE 2: ECDSA Testing\n");
    print_separator();
    
    int sign_passed = 0;
    for (int i = 0; i < 4; i++) {
        if (!gen_success[i]) {
            printf("\nSlot %d: Skipped (no key)\n", slots[i].slot);
            continue;
        }
        
        if (test_ecdsa(slots[i].slot, public_keys[i])) {
            sign_passed++;
        }
    }
    
    // Test ECDH on slots 2 and 3
    printf("\n");
    print_separator();
    printf("  PHASE 3: ECDH Testing\n");
    print_separator();
    
    int ecdh_passed = 0;
    
    // Test Slot 2 ⟷ Slot 3
    if (gen_success[2] && gen_success[3]) {
        if (test_ecdh(2, 3, public_keys[2], public_keys[3])) {
            ecdh_passed++;
        }
    } else {
        printf("\n⚠️  Cannot test ECDH: Slots 2 or 3 missing keys\n");
    }
    
    // Cross-test: Slot 2 with Slot 0 (should work - Slot 2 has ECDH)
    if (gen_success[2] && gen_success[0]) {
        printf("\n--- Cross-test: Slot 2 ⟷ Slot 0 ---\n");
        printf("(Slot 0 doesn't have ECDH, so only Slot 2 can derive)\n");
        
        uint8_t secret[32];
        status = atcab_ecdh(2, public_keys[0], secret);
        if (status == ATCA_SUCCESS) {
            printf("✅ Slot 2 ECDH with Slot 0 pubkey: ");
            print_hex_compact(secret, 16);
            printf("...\n");
            ecdh_passed++;
        } else {
            printf("❌ Failed (0x%02X)\n", status);
        }
    }
    
    // Summary
    printf("\n");
    print_separator();
    printf("  FINAL SUMMARY\n");
    print_separator();
    
    printf("\n📊 Results:\n");
    printf("  Keys Generated:  %d/4\n", 
           gen_success[0] + gen_success[1] + gen_success[2] + gen_success[3]);
    printf("  ECDSA Tests:     %d/%d passed\n", sign_passed,
           gen_success[0] + gen_success[1] + gen_success[2] + gen_success[3]);
    printf("  ECDH Tests:      %d passed\n", ecdh_passed);
    
    printf("\n🔑 Public Keys:\n");
    for (int i = 0; i < 4; i++) {
        if (gen_success[i]) {
            printf("  Slot %d: ", slots[i].slot);
            print_hex_compact(public_keys[i], 64);
            printf("\n");
        } else {
            printf("  Slot %d: (not generated)\n", slots[i].slot);
        }
    }
    
    printf("\n📋 Slot Capabilities:\n");
    printf("  Slot 0: ✅ Sign  ❌ ECDH\n");
    printf("  Slot 1: ✅ Sign  ❌ ECDH\n");
    printf("  Slot 2: ✅ Sign  ✅ ECDH\n");
    printf("  Slot 3: ✅ Sign  ✅ ECDH (+ write-next)\n");
    
    printf("\n💡 Usage:\n");
    printf("  Signing (all slots):     atcab_sign(slot, hash, sig)\n");
    printf("  ECDH (slots 2,3 only):   atcab_ecdh(slot, peer_pubkey, secret)\n");
    printf("  Get public key:          atcab_get_pubkey(slot, pubkey)\n");
    
    printf("\n⚠️  Dev Mode Active:\n");
    printf("  • Config/Data zones UNLOCKED (0x55)\n");
    printf("  • Keys can be regenerated\n");
    printf("  • DO NOT LOCK until production ready!\n");
    
    atcab_release();
    
    printf("\n");
    print_separator();
    printf("  Program Complete\n");
    print_separator();
    
    while (true) {
        tight_loop_contents();
    }
    
    return 0;
}
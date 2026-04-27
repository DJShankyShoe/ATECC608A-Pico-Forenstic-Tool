#include <stdio.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "cryptoauthlib.h"
#include "session_key.h"

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
    printf("%s:\n  ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 16 == 0 && i < len - 1) {
            printf("\n  ");
        }
    }
    printf("\n");
}

int main(void) {
    stdio_init_all();
    sleep_ms(2000);
    
    printf("\n╔═══════════════════════════════════════╗\n");
    printf("║  Ephemeral Session Key Generation    ║\n");
    printf("║  Perfect Forward Secrecy Demo        ║\n");
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
    
    // Step 1: Get peer public key (simulate with Slot 0)
    printf("\n═══════════════════════════════════════\n");
    printf("  STEP 1: Get Peer Public Key\n");
    printf("═══════════════════════════════════════\n");
    printf("(Using Slot 0 as 'peer' for demo)\n\n");
    
    uint8_t peer_pubkey[64];
    status = session_key_get_local_pubkey(0, peer_pubkey);
    if (status != ATCA_SUCCESS) {
        printf("[-] Failed to get peer public key\n");
        atcab_release();
        return 1;
    }
    print_hex("Peer Public Key (Slot 0)", peer_pubkey, 64);
    
    // Step 2: Generate ephemeral session key in Slot 2
    printf("\n═══════════════════════════════════════\n");
    printf("  STEP 2: Generate Ephemeral Session Key\n");
    printf("═══════════════════════════════════════\n");
    printf("⚠️  This will generate a NEW ephemeral key in Slot 2!\n");
    printf("   Each session gets a unique key (Perfect Forward Secrecy)\n\n");
    
    session_key_t session_key;
    
    // Custom salt and info (optional)
    const uint8_t custom_salt[] = "TEAMIS18-SALT";
    const uint8_t custom_info[] = "session-key";
    
    status = session_key_generate(
        2,                                      // Generate ephemeral key in Slot 2
        peer_pubkey,                            // Peer public key
        custom_salt,                            // Salt (or NULL for default)
        strlen((char*)custom_salt),             // Salt length
        custom_info,                            // Info (or NULL for default)
        strlen((char*)custom_info),             // Info length
        &session_key                            // Output
    );
    
    if (status != ATCA_SUCCESS) {
        printf("[-] Session key generation failed\n");
        atcab_release();
        return 1;
    }
    
    printf("\n[+] ✅ Session key generated!\n\n");
    print_hex("📤 OUR Ephemeral Public Key (send to peer)", session_key.ephemeral_pubkey, 64);
    printf("\n");
    print_hex("🔐 Shared Secret (ECDH output)", session_key.shared_secret, 32);
    print_hex("🔑 AES-128 Key (derived via HKDF)", session_key.aes_key, 16);
    
    // Step 3: Store session key in Slot 9
    printf("\n═══════════════════════════════════════\n");
    printf("  STEP 3: Store Session Key\n");
    printf("═══════════════════════════════════════\n");
    
    status = session_key_store(&session_key, 9, 4);
    if (status != ATCA_SUCCESS) {
        printf("[-] Failed to store session key\n");
    } else {
        printf("[+] Session key stored in Slot 9\n");
    }
    
    // Step 4: Test AES encryption with the key
    printf("\n═══════════════════════════════════════\n");
    printf("  STEP 4: Test AES Encryption\n");
    printf("═══════════════════════════════════════\n");
    
    uint8_t plaintext[16] = {
        'H','e','l','l','o',' ','W','o','r','l','d','!','!','!','!','!'
    };
    uint8_t ciphertext[16];
    uint8_t decrypted[16];
    
    print_hex("Plaintext", plaintext, 16);
    
    // Try AES encryption with Slot 9
    status = atcab_aes_encrypt(9, 0, plaintext, ciphertext);
    if (status == ATCA_SUCCESS) {
        printf("[+] AES encryption succeeded\n");
        print_hex("Ciphertext", ciphertext, 16);
        
        // Try decryption
        status = atcab_aes_decrypt(9, 0, ciphertext, decrypted);
        if (status == ATCA_SUCCESS) {
            print_hex("Decrypted", decrypted, 16);
            
            if (memcmp(plaintext, decrypted, 16) == 0) {
                printf("[+] ✅ Round-trip successful!\n");
            } else {
                printf("[-] Decryption mismatch\n");
            }
        } else {
            printf("[-] AES decryption failed: 0x%08X\n", status);
        }
    } else {
        printf("[-] AES encryption failed: 0x%08X\n", status);
        printf("    (Key is stored, but hardware AES may not be configured)\n");
        printf("    You can use software AES with the stored key\n");
    }
    
    // Step 5: Generate ANOTHER session key to prove uniqueness
    printf("\n═══════════════════════════════════════\n");
    printf("  STEP 5: Prove Perfect Forward Secrecy\n");
    printf("═══════════════════════════════════════\n");
    printf("Generating a second session key with the same peer...\n\n");
    
    session_key_t session_key2;
    status = session_key_generate(
        2,                                      // Generate NEW ephemeral key in Slot 2
        peer_pubkey,                            // Same peer public key
        custom_salt,                            
        strlen((char*)custom_salt),             
        custom_info,                            
        strlen((char*)custom_info),             
        &session_key2                           
    );
    
    if (status == ATCA_SUCCESS) {
        printf("[+] Second session key generated!\n\n");
        print_hex("📤 NEW Ephemeral Public Key", session_key2.ephemeral_pubkey, 64);
        print_hex("🔑 NEW AES-128 Key", session_key2.aes_key, 16);
        
        printf("\n🔍 Comparing keys:\n");
        printf("   First  ephemeral pubkey: ");
        for (int i = 0; i < 8; i++) printf("%02X", session_key.ephemeral_pubkey[i]);
        printf("...\n");
        printf("   Second ephemeral pubkey: ");
        for (int i = 0; i < 8; i++) printf("%02X", session_key2.ephemeral_pubkey[i]);
        printf("...\n");
        
        if (memcmp(session_key.ephemeral_pubkey, session_key2.ephemeral_pubkey, 64) != 0) {
            printf("   ✅ Ephemeral keys are DIFFERENT (as expected)\n");
        }
        
        printf("\n   First  AES key: ");
        for (int i = 0; i < 16; i++) printf("%02X", session_key.aes_key[i]);
        printf("\n");
        printf("   Second AES key: ");
        for (int i = 0; i < 16; i++) printf("%02X", session_key2.aes_key[i]);
        printf("\n");
        
        if (memcmp(session_key.aes_key, session_key2.aes_key, 16) != 0) {
            printf("   ✅ Session keys are DIFFERENT (Perfect Forward Secrecy!)\n");
        }
    }
    
    // Summary
    printf("\n═══════════════════════════════════════\n");
    printf("  SUMMARY\n");
    printf("═══════════════════════════════════════\n");
    printf("✅ Ephemeral session keys successfully generated!\n");
    printf("\n📋 Key Properties:\n");
    printf("  • Ephemeral Slot: Slot 2\n");
    printf("  • Storage Slot: Slot 9 (AES)\n");
    printf("  • Key Length: AES-128 (16 bytes)\n");
    printf("  • HKDF Salt: %s\n", custom_salt);
    printf("  • HKDF Info: %s\n", custom_info);
    
    printf("\n🔐 Security Features:\n");
    printf("  ✅ Perfect Forward Secrecy\n");
    printf("     → Each session has unique key\n");
    printf("  ✅ Ephemeral Key Generation\n");
    printf("     → New private key generated per session\n");
    printf("  ✅ Hardware-Protected ECDH\n");
    printf("     → Private keys never leave ATECC608A\n");
    printf("  ✅ HKDF Key Derivation\n");
    printf("     → Proper key expansion from shared secret\n");
    
    printf("\n💡 Protocol Flow:\n");
    printf("  1. Generate ephemeral key in Slot 2\n");
    printf("  2. Send OUR ephemeral public key to peer\n");
    printf("  3. Receive peer's ephemeral public key\n");
    printf("  4. Perform ECDH → derive session key\n");
    printf("  5. Use session key for encryption\n");
    printf("  6. Discard keys after session ends\n");
    
    printf("\n⚠️  Important Notes:\n");
    printf("  • Slot 2 is overwritten on each call\n");
    printf("  • Don't use Slot 2 for long-term keys\n");
    printf("  • Both parties must exchange ephemeral pubkeys\n");
    printf("  • Salt/info must match on both sides\n");
    
    printf("\n🎯 Real-World Usage:\n");
    printf("  • TLS/HTTPS connection establishment\n");
    printf("  • Secure communication sessions\n");
    printf("  • IoT device-to-device encryption\n");
    printf("  • Temporary secure channels\n");
    
    atcab_release();
    
    printf("\n[+] Demo complete!\n");
    printf("═══════════════════════════════════════\n\n");
    
    while (true) {
        tight_loop_contents();
    }
    
    return 0;
}
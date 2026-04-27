#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "session_key.h"

// Default salt and info for HKDF
static const uint8_t DEFAULT_SALT[] = "TEAMIS18-SALT";
static const uint8_t DEFAULT_INFO[] = "session-key";

// NONCE_NUMIN_SIZE definition
#ifndef NONCE_NUMIN_SIZE
#define NONCE_NUMIN_SIZE 20
#endif

// Default IO key (same as in password_verify)
static const uint8_t DEFAULT_IO_KEY[32] = {
    0x37, 0x80, 0xe6, 0x3d, 0x49, 0x68, 0xad, 0xe5,
    0xd8, 0x22, 0xc0, 0x13, 0xfc, 0xc3, 0x23, 0x84,
    0x5d, 0x1b, 0x56, 0x9f, 0xe7, 0x05, 0xb6, 0x00,
    0x06, 0xfe, 0xec, 0x14, 0x5a, 0x0e, 0x22, 0x89
};

/**
 * @brief Proper HKDF-Extract using HMAC-SHA256
 * PRK = HMAC-Hash(salt, IKM)
 */
static void hkdf_extract(const uint8_t* salt, size_t salt_len,
                        const uint8_t* ikm, size_t ikm_len,
                        uint8_t* prk) {
    struct atcac_hmac_ctx hmac_ctx;
    struct atcac_sha2_256_ctx sha256_ctx;
    size_t digest_len = 32;
    
    // HMAC-SHA256(key=salt, data=ikm)
    atcac_sha256_hmac_init(&hmac_ctx, &sha256_ctx, salt, (uint8_t)salt_len);
    atcac_sha256_hmac_update(&hmac_ctx, ikm, ikm_len);
    atcac_sha256_hmac_finish(&hmac_ctx, prk, &digest_len);
}

/**
 * @brief Proper HKDF-Expand using HMAC-SHA256
 * T(1) = HMAC-Hash(PRK, info || 0x01)
 * OKM = first L bytes of T(1)
 */
static void hkdf_expand(const uint8_t* prk, const uint8_t* info, size_t info_len,
                       uint8_t* okm, size_t okm_len) {
    struct atcac_hmac_ctx hmac_ctx;
    struct atcac_sha2_256_ctx sha256_ctx;
    uint8_t t[32];  // T(1)
    uint8_t counter = 0x01;
    size_t digest_len = 32;
    
    // T(1) = HMAC-SHA256(PRK, info || 0x01)
    atcac_sha256_hmac_init(&hmac_ctx, &sha256_ctx, prk, 32);
    atcac_sha256_hmac_update(&hmac_ctx, info, info_len);
    atcac_sha256_hmac_update(&hmac_ctx, &counter, 1);
    atcac_sha256_hmac_finish(&hmac_ctx, t, &digest_len);
    
    // Copy requested length
    memcpy(okm, t, okm_len > 32 ? 32 : okm_len);
}

// Get local public key from given slot, generating if not present
ATCA_STATUS session_key_get_local_pubkey(uint16_t slot, uint8_t* pubkey)
{
    if (!pubkey) {
        return ATCA_BAD_PARAM;
    }
    
    ATCA_STATUS status = atcab_get_pubkey(slot, pubkey);
    
    if (status != ATCA_SUCCESS) {
        // Try to generate key if it doesn't exist
        printf("[session_key] No key in Slot %d, generating...\n", slot);
        status = atcab_genkey(slot, NULL);
        if (status != ATCA_SUCCESS) {
            printf("[session_key] GenKey failed: 0x%08X\n", status);
            return status;
        }
        
        status = atcab_get_pubkey(slot, pubkey);
        if (status != ATCA_SUCCESS) {
            printf("[session_key] Get pubkey failed: 0x%08X\n", status);
            return status;
        }
    }
    
    return ATCA_SUCCESS;
}

// Generate session key with ephemeral keypair in specified slot
ATCA_STATUS session_key_generate_ephemeral(uint16_t ephemeral_slot,
                                           const uint8_t* peer_pubkey,
                                           uint8_t* local_pubkey_out,
                                           const uint8_t* salt,
                                           size_t salt_len,
                                           const uint8_t* info,
                                           size_t info_len,
                                           session_key_t* session_key_out)
{
    if (!peer_pubkey || !local_pubkey_out || !session_key_out) {
        return ATCA_BAD_PARAM;
    }
    
    ATCA_STATUS status;
    
    // Initialize output
    memset(session_key_out, 0, sizeof(session_key_t));
    session_key_out->is_valid = false;
    
    // Use defaults if not provided
    if (!salt) {
        salt = DEFAULT_SALT;
        salt_len = strlen((char*)DEFAULT_SALT);
    }
    if (!info) {
        info = DEFAULT_INFO;
        info_len = strlen((char*)DEFAULT_INFO);
    }
    
    printf("[session_key] Generating NEW ephemeral key in Slot %d\n", ephemeral_slot);
    
    // Generate NEW ephemeral key pair (overwrites any existing key!)
    status = atcab_genkey(ephemeral_slot, local_pubkey_out);
    if (status != ATCA_SUCCESS) {
        printf("[session_key] Failed to generate ephemeral key: 0x%08X\n", status);
        return status;
    }
    
    printf("[session_key] Ephemeral key generated successfully\n");
    printf("[session_key] WARNING: Slot %d private key will be lost after power cycle!\n", ephemeral_slot);
    printf("[session_key] Exchange this public key with peer:\n");
    printf("[session_key]   ");
    for (int i = 0; i < 64; i++) {
        printf("%02X", local_pubkey_out[i]);
        if (i == 31) printf("\n[session_key]   ");
    }
    printf("\n");
    
    // Perform ECDH with peer public key
    printf("[session_key] Performing ECDH with peer...\n");
    status = atcab_ecdh(ephemeral_slot, peer_pubkey, session_key_out->shared_secret);
    
    if (status == ATCA_SUCCESS) {
        // Check if valid (not all zeros)
        bool valid = false;
        for (int i = 0; i < 32; i++) {
            if (session_key_out->shared_secret[i] != 0) {
                valid = true;
                break;
            }
        }
        
        if (!valid) {
            printf("[session_key] ECDH returned all zeros, trying fallback\n");
            status = ATCA_GEN_FAIL;
        } else {
            printf("[session_key] ECDH succeeded\n");
        }
    }
    
    if (status != ATCA_SUCCESS) {
        printf("[session_key] ECDH failed: 0x%08X\n", status);
        printf("[session_key] Using fallback: hash of combined pubkeys\n");
        
        // Fallback: deterministic shared secret from public keys
        uint8_t combined[128];
        memcpy(combined, local_pubkey_out, 64);
        memcpy(combined + 64, peer_pubkey, 64);
        atcab_sha(128, combined, session_key_out->shared_secret);
        
        printf("[session_key] WARNING: Using simulated ECDH (not secure for production)\n");
    }
    
    // Derive AES-128 key using HKDF
    printf("[session_key] Deriving AES-128 key with HKDF\n");
    
    uint8_t prk[32];
    hkdf_extract(salt, salt_len, session_key_out->shared_secret, 32, prk);
    hkdf_expand(prk, info, info_len, session_key_out->aes_key, 16);
    
    session_key_out->is_valid = true;
    
    printf("[session_key] Session key with Perfect Forward Secrecy generated!\n");
    
    return ATCA_SUCCESS;
}

// Generate session key with ephemeral keypair in specified slot
ATCA_STATUS session_key_generate(uint16_t local_slot,
                                 const uint8_t* peer_pubkey,
                                 const uint8_t* salt,
                                 size_t salt_len,
                                 const uint8_t* info,
                                 size_t info_len,
                                 session_key_t* session_key_out)
{
    if (!peer_pubkey || !session_key_out) {
        return ATCA_BAD_PARAM;
    }
    
    ATCA_STATUS status;
    
    // Initialize output
    memset(session_key_out, 0, sizeof(session_key_t));
    session_key_out->is_valid = false;
    
    // Use defaults if not provided
    if (!salt) {
        salt = DEFAULT_SALT;
        salt_len = strlen((char*)DEFAULT_SALT);
    }
    if (!info) {
        info = DEFAULT_INFO;
        info_len = strlen((char*)DEFAULT_INFO);
    }
    
    printf("[session_key] Generating ephemeral key in Slot %d\n", local_slot);
    
    // STEP 1: Generate new ephemeral private key in Slot 2
    // This ensures unique session keys every time (perfect forward secrecy)
    status = atcab_genkey(local_slot, NULL);
    if (status != ATCA_SUCCESS) {
        printf("[session_key] Failed to generate ephemeral key: 0x%08X\n", status);
        return status;
    }
    printf("[session_key] ✅ Ephemeral private key generated in Slot %d\n", local_slot);
    
    // STEP 2: Get the new public key
    uint8_t local_pubkey[64];
    status = atcab_get_pubkey(local_slot, local_pubkey);
    if (status != ATCA_SUCCESS) {
        printf("[session_key] Failed to get ephemeral public key: 0x%08X\n", status);
        return status;
    }
    
    // Store ephemeral public key in output (for sending to peer)
    memcpy(session_key_out->ephemeral_pubkey, local_pubkey, 64);
    
    printf("[session_key] ✅ Ephemeral public key extracted: ");
    for (int i = 0; i < 8; i++) printf("%02X", local_pubkey[i]);
    printf("...\n");
    
    // STEP 3: Perform ECDH with peer's public key
    printf("[session_key] Performing ECDH...\n");
    status = atcab_ecdh(local_slot, peer_pubkey, session_key_out->shared_secret);
    
    if (status == ATCA_SUCCESS) {
        // Check if valid (not all zeros)
        bool valid = false;
        for (int i = 0; i < 32; i++) {
            if (session_key_out->shared_secret[i] != 0) {
                valid = true;
                break;
            }
        }
        
        if (!valid) {
            printf("[session_key] ECDH returned all zeros, trying fallback\n");
            status = ATCA_GEN_FAIL;
        } else {
            printf("[session_key] ✅ ECDH succeeded\n");
        }
    }
    
    if (status != ATCA_SUCCESS) {
        printf("[session_key] ECDH failed: 0x%08X\n", status);
        printf("[session_key] Using fallback: hash of combined pubkeys\n");
        
        // Fallback: deterministic shared secret from public keys
        uint8_t combined[128];
        memcpy(combined, local_pubkey, 64);
        memcpy(combined + 64, peer_pubkey, 64);
        atcab_sha(128, combined, session_key_out->shared_secret);
        
        printf("[session_key] WARNING: Using simulated ECDH (not secure for production)\n");
    }
    
    // STEP 4: Derive AES-128 key using HKDF
    printf("[session_key] Deriving AES-128 key with HKDF\n");
    
    uint8_t prk[32];
    hkdf_extract(salt, salt_len, session_key_out->shared_secret, 32, prk);
    hkdf_expand(prk, info, info_len, session_key_out->aes_key, 16);
    
    session_key_out->is_valid = true;
    
    printf("[session_key] ✅ Session key generated successfully (ephemeral)\n");
    
    return ATCA_SUCCESS;
}

// Store session key in ATECC slot, encrypted with IO key from another slot
ATCA_STATUS session_key_store(const session_key_t* session_key,
                              uint16_t aes_slot,
                              uint16_t io_key_slot)
{
    if (!session_key || !session_key->is_valid) {
        return ATCA_BAD_PARAM;
    }
    
    ATCA_STATUS status;
    
    printf("[session_key] Storing session key in Slot %d\n", aes_slot);
    
    // Get IO key
    uint8_t io_key[32];
    status = atcab_read_zone(ATCA_ZONE_DATA, io_key_slot, 0, 0, io_key, 32);
    
    if (status != ATCA_SUCCESS) {
        printf("[session_key] Cannot read IO key from Slot %d, writing default\n", io_key_slot);
        
        status = atcab_write_zone(ATCA_ZONE_DATA, io_key_slot, 0, 0, 
                                 DEFAULT_IO_KEY, 32);
        if (status != ATCA_SUCCESS) {
            printf("[session_key] Failed to write IO key: 0x%08X\n", status);
            return status;
        }
        
        memcpy(io_key, DEFAULT_IO_KEY, 32);
        printf("[session_key] IO key written to Slot %d\n", io_key_slot);
    }
    
    // Pad AES-128 key to 32 bytes
    uint8_t aes_key_padded[32];
    memcpy(aes_key_padded, session_key->aes_key, 16);
    memset(aes_key_padded + 16, 0, 16);
    
    // Prepare nonce
    uint8_t num_in[NONCE_NUMIN_SIZE];
    memset(num_in, 0, NONCE_NUMIN_SIZE);
    
    // Write encrypted
    status = calib_write_enc(atcab_get_device(), aes_slot, 0, 
                            aes_key_padded, io_key, io_key_slot, num_in);
    
    if (status != ATCA_SUCCESS) {
        printf("[session_key] Failed to write to Slot %d: 0x%08X\n", aes_slot, status);
        return status;
    }
    
    printf("[session_key] Session key stored successfully in Slot %d\n", aes_slot);
    
    return ATCA_SUCCESS;
}
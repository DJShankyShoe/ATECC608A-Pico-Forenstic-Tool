#ifndef SESSION_KEY_H
#define SESSION_KEY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "cryptoauthlib.h"

#ifdef __cplusplus
extern "C" {
#endif

// Session key structure
typedef struct {
    uint8_t aes_key[16];          // AES-128 key (derived from ECDH)
    uint8_t shared_secret[32];    // ECDH shared secret
    uint8_t ephemeral_pubkey[64]; // Our ephemeral public key (to send to peer)
    bool is_valid;                // Validity flag
} session_key_t;

/**
 * @brief Generate session key using ECDH with ephemeral keys
 * 
 * This function provides perfect forward secrecy by:
 * 1. Generating a NEW ephemeral ECC P-256 private key in local_slot
 * 2. Extracting the ephemeral public key (stored in session_key_out->ephemeral_pubkey)
 * 3. Performing ECDH with peer's public key
 * 4. Deriving AES-128 key using HKDF
 * 
 * IMPORTANT: The ephemeral public key (session_key_out->ephemeral_pubkey)
 *            MUST be sent to the peer so they can derive the same session key.
 *            Each call generates a unique key (Perfect Forward Secrecy).
 * 
 * @param local_slot Local ECC slot for ephemeral key (recommend: 2)
 *                   WARNING: This overwrites any existing key in this slot!
 * @param peer_pubkey Peer's public key (64 bytes)
 * @param salt Salt for HKDF (can be NULL for default "TEAMIS18-SALT")
 * @param salt_len Salt length
 * @param info Info string for HKDF (can be NULL for default "session-key")
 * @param info_len Info length
 * @param session_key_out Pointer to session_key_t to store result
 * @return ATCA_STATUS
 *         - ATCA_SUCCESS if key generated successfully
 *         - Error code otherwise
 * 
 * @note This overwrites any existing key in local_slot with a fresh ephemeral key
 * @note Each call generates a unique session key (perfect forward secrecy)
 * 
 * @example
 * // Generate session key
 * session_key_t sk;
 * status = session_key_generate(2, peer_pub, NULL, 0, NULL, 0, &sk);
 * 
 * // Send sk.ephemeral_pubkey to peer
 * send_to_peer(sk.ephemeral_pubkey, 64);
 * 
 * // Use sk.aes_key for encryption
 * atcab_aes_encrypt(9, 0, plaintext, ciphertext);
 */
ATCA_STATUS session_key_generate(uint16_t local_slot,
                                 const uint8_t* peer_pubkey,
                                 const uint8_t* salt,
                                 size_t salt_len,
                                 const uint8_t* info,
                                 size_t info_len,
                                 session_key_t* session_key_out);

/**
 * @brief Store session key in ATECC608A AES slot
 * 
 * @param session_key Session key to store
 * @param aes_slot AES slot to store in (e.g., 9, 10, 11)
 * @param io_key_slot IO key slot for encrypted write (e.g., 4)
 * @return ATCA_STATUS
 */
ATCA_STATUS session_key_store(const session_key_t* session_key,
                              uint16_t aes_slot,
                              uint16_t io_key_slot);

/**
 * @brief Get local public key for ECDH
 * 
 * @param slot ECC slot (0-3)
 * @param pubkey Output buffer for public key (64 bytes)
 * @return ATCA_STATUS
 */
ATCA_STATUS session_key_get_local_pubkey(uint16_t slot, uint8_t* pubkey);

#ifdef __cplusplus
}
#endif

#endif // SESSION_KEY_H
#ifndef AES_OPERATIONS_H
#define AES_OPERATIONS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "cryptoauthlib.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Generate a random Initialization Vector (IV) using ATECC608 RNG
 * 
 * @param iv Output buffer for IV (16 bytes)
 * @return ATCA_STATUS
 */
ATCA_STATUS generate_iv(uint8_t* iv);

/**
 * @brief AES-128 ECB encryption
 * 
 * @param key_slot Slot containing AES-128 key (e.g., 9, 10, 11)
 * @param plaintext Input plaintext (16 bytes)
 * @param ciphertext Output ciphertext (16 bytes)
 * @return ATCA_STATUS
 */
ATCA_STATUS aes_ecb_encrypt(uint16_t key_slot,
                            const uint8_t* plaintext,
                            uint8_t* ciphertext);

/**
 * @brief AES-128 ECB decryption
 * 
 * @param key_slot Slot containing AES-128 key (e.g., 9, 10, 11)
 * @param ciphertext Input ciphertext (16 bytes)
 * @param plaintext Output plaintext (16 bytes)
 * @return ATCA_STATUS
 */
ATCA_STATUS aes_ecb_decrypt(uint16_t key_slot,
                            const uint8_t* ciphertext,
                            uint8_t* plaintext);

/**
 * @brief AES-128 CBC encryption
 * 
 * @param key_slot Slot containing AES-128 key
 * @param iv Initialization vector (16 bytes)
 * @param plaintext Input plaintext (multiple of 16 bytes)
 * @param plaintext_len Length of plaintext (must be multiple of 16)
 * @param ciphertext Output ciphertext (same length as plaintext)
 * @return ATCA_STATUS
 */
ATCA_STATUS aes_cbc_encrypt(uint16_t key_slot,
                            const uint8_t* iv,
                            const uint8_t* plaintext,
                            size_t plaintext_len,
                            uint8_t* ciphertext);

/**
 * @brief AES-128 CBC decryption
 * 
 * @param key_slot Slot containing AES-128 key
 * @param iv Initialization vector (16 bytes)
 * @param ciphertext Input ciphertext (multiple of 16 bytes)
 * @param ciphertext_len Length of ciphertext (must be multiple of 16)
 * @param plaintext Output plaintext (same length as ciphertext)
 * @return ATCA_STATUS
 */
ATCA_STATUS aes_cbc_decrypt(uint16_t key_slot,
                            const uint8_t* iv,
                            const uint8_t* ciphertext,
                            size_t ciphertext_len,
                            uint8_t* plaintext);

/**
 * @brief AES-128 GCM encryption with authentication
 * 
 * @param key_slot Slot containing AES-128 key
 * @param iv Initialization vector (12 bytes recommended for GCM)
 * @param iv_len IV length (typically 12)
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param plaintext Input plaintext
 * @param plaintext_len Plaintext length
 * @param ciphertext Output ciphertext (same length as plaintext)
 * @param tag Output authentication tag (16 bytes)
 * @return ATCA_STATUS
 */
ATCA_STATUS aes_gcm_encrypt(uint16_t key_slot,
                            const uint8_t* iv,
                            size_t iv_len,
                            const uint8_t* aad,
                            size_t aad_len,
                            const uint8_t* plaintext,
                            size_t plaintext_len,
                            uint8_t* ciphertext,
                            uint8_t* tag);

/**
 * @brief AES-128 GCM decryption with authentication
 * 
 * @param key_slot Slot containing AES-128 key
 * @param iv Initialization vector (12 bytes recommended)
 * @param iv_len IV length
 * @param aad Additional authenticated data (can be NULL)
 * @param aad_len AAD length
 * @param ciphertext Input ciphertext
 * @param ciphertext_len Ciphertext length
 * @param tag Authentication tag to verify (16 bytes)
 * @param plaintext Output plaintext (same length as ciphertext)
 * @return ATCA_STATUS
 *         - ATCA_SUCCESS if decryption and authentication successful
 *         - Error code if authentication fails
 */
ATCA_STATUS aes_gcm_decrypt(uint16_t key_slot,
                            const uint8_t* iv,
                            size_t iv_len,
                            const uint8_t* aad,
                            size_t aad_len,
                            const uint8_t* ciphertext,
                            size_t ciphertext_len,
                            const uint8_t* tag,
                            uint8_t* plaintext);

#ifdef __cplusplus
}
#endif

#endif // AES_OPERATIONS_H
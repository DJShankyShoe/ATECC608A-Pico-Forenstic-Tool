/**
 * fr_data.h
 * Forensic Data Storage Module
 * Handles encrypted storage of telemetry data to SD card using AES-GCM
 */

#ifndef FR_DATA_H
#define FR_DATA_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Return codes
#define FR_DATA_OK              0
#define FR_DATA_ERROR          -1
#define FR_DATA_NO_SESSION     -2
#define FR_DATA_CRYPTO_ERROR   -3
#define FR_DATA_STORAGE_ERROR  -4
#define FR_DATA_INVALID_PARAM  -5

// Configuration
#define FR_DATA_AAD "Team18-IS"
#define FR_DATA_IV_SIZE 12      // GCM recommended IV size
#define FR_DATA_TAG_SIZE 16     // GCM authentication tag size
#define FR_DATA_MAX_CHUNK 4096  // Maximum chunk size

/**
 * Initialize the forensic data storage module
 * @return FR_DATA_OK on success, error code otherwise
 */
int fr_data_init(void);

/**
 * Start a new telemetry collection session
 * Creates a new file on SD card for encrypted data
 * @param filename Name of file to create (e.g., "telem_001.dat")
 * @return FR_DATA_OK on success, error code otherwise
 */
int fr_data_start_session(const char* filename);

/**
 * Store a telemetry chunk with GCM encryption
 * Encrypts the data and appends to current session file
 * Format: [IV(12)] [Ciphertext(variable)] [Tag(16)]
 * @param data Plaintext data to encrypt and store
 * @param len Length of data
 * @param seq Sequence number for logging
 * @return FR_DATA_OK on success, error code otherwise
 */
int fr_data_store_chunk(const uint8_t* data, size_t len, uint32_t seq);

/**
 * End the current telemetry collection session
 * Closes the file and cleans up
 * @return FR_DATA_OK on success, error code otherwise
 */
int fr_data_end_session(void);

/**
 * Check if a session is currently active
 * @return true if active, false otherwise
 */
bool fr_data_is_session_active(void);

/**
 * Get current session filename
 * @return Filename or NULL if no active session
 */
const char* fr_data_get_session_filename(void);

/**
 * Get statistics for current session
 * @param chunks_stored Pointer to store number of chunks written
 * @param bytes_stored Pointer to store total bytes written (encrypted)
 * @return FR_DATA_OK on success, error code otherwise
 */
int fr_data_get_session_stats(uint32_t* chunks_stored, uint32_t* bytes_stored);

#endif // FR_DATA_H
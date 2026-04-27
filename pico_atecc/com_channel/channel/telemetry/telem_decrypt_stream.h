/**
 * telem_decrypt_stream.h
 * Streaming Telemetry File Decryption
 * Decrypts one chunk at a time to avoid memory overload
 */

#ifndef TELEM_DECRYPT_STREAM_H
#define TELEM_DECRYPT_STREAM_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "ff.h"

// Return codes
#define TELEM_STREAM_OK             0
#define TELEM_STREAM_ERROR         -1
#define TELEM_STREAM_END_OF_FILE   -2
#define TELEM_STREAM_CRYPTO_ERROR  -3
#define TELEM_STREAM_FORMAT_ERROR  -4

// Streaming context
typedef struct {
    FIL file;
    bool file_open;
    size_t file_size;
    size_t bytes_read;
    uint32_t chunks_decrypted;
    bool header_verified;
} telem_stream_ctx_t;

/**
 * Initialize streaming decryption context
 * @param ctx Context to initialize
 * @param filename Telemetry file to decrypt
 * @return TELEM_STREAM_OK on success
 */
int telem_stream_open(telem_stream_ctx_t *ctx, const char *filename);

/**
 * Decrypt next chunk from file
 * @param ctx Streaming context
 * @param output_buffer Buffer for decrypted data (at least 4096 bytes)
 * @param decrypted_size Actual size of decrypted chunk
 * @param sequence Sequence number of this chunk
 * @return TELEM_STREAM_OK on success, TELEM_STREAM_END_OF_FILE when done
 */
int telem_stream_decrypt_next(telem_stream_ctx_t *ctx, 
                               uint8_t *output_buffer,
                               size_t *decrypted_size,
                               uint32_t *sequence);

/**
 * Close streaming context
 * @param ctx Context to close
 */
void telem_stream_close(telem_stream_ctx_t *ctx);

/**
 * Check if file is telemetry file (quick check)
 * @param filename File to check
 * @return true if telemetry file
 */
bool telem_is_telemetry_file_quick(const char *filename);

#endif // TELEM_DECRYPT_STREAM_H
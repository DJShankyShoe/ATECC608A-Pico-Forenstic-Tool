/**
 * telem_decrypt_stream.c
 * Streaming Telemetry Decryption Implementation
 */

#include "telem_decrypt_stream.h"
#include "sd_card.h"
#include "aes_op.h"
#include "pico/stdlib.h"
#include <stdio.h>
#include <string.h>

#define FR_DATA_HEADER "FR-DATA-GCM-v1\n"
#define FR_DATA_HEADER_LEN 15
#define FR_DATA_AAD "Team18-IS"
#define FR_DATA_IV_SIZE 12
#define FR_DATA_TAG_SIZE 16
#define SESSION_AES_SLOT 9

bool telem_is_telemetry_file_quick(const char *filename) {
    if (!filename) {
        return false;
    }
    
    // Quick check - just check filename pattern
    return (strncmp(filename, "telem_", 6) == 0);
}

int telem_stream_open(telem_stream_ctx_t *ctx, const char *filename) {
    if (!ctx || !filename) {
        return TELEM_STREAM_ERROR;
    }
    
    // Initialize context
    memset(ctx, 0, sizeof(telem_stream_ctx_t));
    
    // Get file size
    if (sd_get_file_size(filename, &ctx->file_size) != SD_OK) {
        printf("[Stream] Failed to get file size\n");
        fflush(stdout);
        return TELEM_STREAM_ERROR;
    }
    
    // Open file for streaming
    if (sd_file_open(filename, &ctx->file) != SD_OK) {
        printf("[Stream] Failed to open file\n");
        fflush(stdout);
        return TELEM_STREAM_ERROR;
    }
    
    ctx->file_open = true;
    
    // Read and verify header
    uint8_t header[FR_DATA_HEADER_LEN];
    size_t bytes_read;
    
    if (sd_file_read(&ctx->file, header, FR_DATA_HEADER_LEN, &bytes_read) != SD_OK ||
        bytes_read != FR_DATA_HEADER_LEN) {
        printf("[Stream] Failed to read header\n");
        fflush(stdout);
        telem_stream_close(ctx);
        return TELEM_STREAM_ERROR;
    }
    
    if (memcmp(header, FR_DATA_HEADER, FR_DATA_HEADER_LEN) != 0) {
        printf("[Stream] Invalid header\n");
        fflush(stdout);
        telem_stream_close(ctx);
        return TELEM_STREAM_FORMAT_ERROR;
    }
    
    ctx->header_verified = true;
    ctx->bytes_read = FR_DATA_HEADER_LEN;
    
    printf("[Stream] Opened file: %zu bytes\n", ctx->file_size);
    fflush(stdout);
    
    return TELEM_STREAM_OK;
}

int telem_stream_decrypt_next(telem_stream_ctx_t *ctx,
                               uint8_t *output_buffer,
                               size_t *decrypted_size,
                               uint32_t *sequence) {
    if (!ctx || !ctx->file_open || !output_buffer || !decrypted_size || !sequence) {
        return TELEM_STREAM_ERROR;
    }
    
    // Check if we've reached end of file
    if (ctx->bytes_read >= ctx->file_size) {
        return TELEM_STREAM_END_OF_FILE;
    }
    
    // Read chunk header (SEQ + LEN = 8 bytes)
    uint8_t header[8];
    size_t bytes_read;
    
    printf("[Stream] Reading chunk header...\n");
    fflush(stdout);
    
    printf("[Stream] Calling sd_file_read for 8 bytes...\n");
    fflush(stdout);
    
    int result = sd_file_read(&ctx->file, header, 8, &bytes_read);
    
    printf("[Stream] sd_file_read returned: %d, bytes_read: %zu\n", result, bytes_read);
    fflush(stdout);
    
    if (result != SD_OK || bytes_read != 8) {
        printf("[Stream] Failed to read chunk header (result=%d, got %zu bytes)\n", result, bytes_read);
        fflush(stdout);
        return TELEM_STREAM_ERROR;
    }
    
    ctx->bytes_read += 8;
    
    // Parse sequence number
    uint32_t seq = ((uint32_t)header[0] << 24) |
                   ((uint32_t)header[1] << 16) |
                   ((uint32_t)header[2] << 8) |
                   ((uint32_t)header[3]);
    
    // Parse plaintext length
    uint32_t plaintext_len = ((uint32_t)header[4] << 24) |
                             ((uint32_t)header[5] << 16) |
                             ((uint32_t)header[6] << 8) |
                             ((uint32_t)header[7]);
    
    printf("[Stream] Seq=%u Len=%u\n", seq, plaintext_len);
    fflush(stdout);
    
    // Sanity check
    if (plaintext_len > 4096) {
        printf("[Stream] Invalid length: %u\n", plaintext_len);
        fflush(stdout);
        return TELEM_STREAM_FORMAT_ERROR;
    }
    
    // Read IV
    uint8_t iv[FR_DATA_IV_SIZE];
    printf("[Stream] Reading IV...\n");
    fflush(stdout);
    
    if (sd_file_read(&ctx->file, iv, FR_DATA_IV_SIZE, &bytes_read) != SD_OK ||
        bytes_read != FR_DATA_IV_SIZE) {
        printf("[Stream] Failed to read IV\n");
        fflush(stdout);
        return TELEM_STREAM_ERROR;
    }
    
    ctx->bytes_read += FR_DATA_IV_SIZE;
    
    // Read ciphertext into static buffer to avoid stack overflow
    static uint8_t ciphertext_buffer[4096];
    printf("[Stream] Reading ciphertext (%u bytes)...\n", plaintext_len);
    fflush(stdout);
    
    if (sd_file_read(&ctx->file, ciphertext_buffer, plaintext_len, &bytes_read) != SD_OK ||
        bytes_read != plaintext_len) {
        printf("[Stream] Failed to read ciphertext\n");
        fflush(stdout);
        return TELEM_STREAM_ERROR;
    }
    
    ctx->bytes_read += plaintext_len;
    
    // Read tag
    uint8_t tag[FR_DATA_TAG_SIZE];
    printf("[Stream] Reading tag...\n");
    fflush(stdout);
    
    if (sd_file_read(&ctx->file, tag, FR_DATA_TAG_SIZE, &bytes_read) != SD_OK ||
        bytes_read != FR_DATA_TAG_SIZE) {
        printf("[Stream] Failed to read tag\n");
        fflush(stdout);
        return TELEM_STREAM_ERROR;
    }
    
    ctx->bytes_read += FR_DATA_TAG_SIZE;
    
    printf("[Stream] All data read, starting decrypt...\n");
    fflush(stdout);
    
    // Decrypt directly to output_buffer (no temp buffer needed!)
    const uint8_t *aad = (const uint8_t *)FR_DATA_AAD;
    size_t aad_len = strlen(FR_DATA_AAD);
    
    printf("[Stream] Calling aes_gcm_decrypt...\n");
    fflush(stdout);
    
    ATCA_STATUS status = aes_gcm_decrypt(
        SESSION_AES_SLOT,
        iv,
        FR_DATA_IV_SIZE,
        aad,
        aad_len,
        ciphertext_buffer,  // Input from static buffer
        plaintext_len,
        tag,
        output_buffer       // Output directly to caller's buffer
    );
    
    printf("[Stream] Decrypt returned: 0x%08X\n", status);
    fflush(stdout);
    
    if (status != ATCA_SUCCESS) {
        printf("[Stream] Decryption failed: 0x%08X\n", status);
        fflush(stdout);
        return TELEM_STREAM_CRYPTO_ERROR;
    }
    
    *decrypted_size = plaintext_len;
    *sequence = seq;
    ctx->chunks_decrypted++;
    
    // Give ATECC608 recovery time
    sleep_ms(100);
    
    return TELEM_STREAM_OK;
}

void telem_stream_close(telem_stream_ctx_t *ctx) {
    if (!ctx) {
        return;
    }
    
    if (ctx->file_open) {
        sd_file_close(&ctx->file);
        ctx->file_open = false;
    }
    
    printf("[Stream] Closed: %u chunks decrypted\n", ctx->chunks_decrypted);
    fflush(stdout);
}
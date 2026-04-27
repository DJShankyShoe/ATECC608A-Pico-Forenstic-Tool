/**
 * fr_data.c
 * Forensic Data Storage Module Implementation
 */

#include "fr_data.h"
#include "sd_card.h"
#include "aes_op.h"
#include <stdio.h>
#include <string.h>

#define SESSION_AES_SLOT 9

// Session state
static struct {
    bool active;
    char filename[256];
    uint32_t chunks_stored;
    uint32_t bytes_stored;
} session_state = {0};

int fr_data_init(void) {
    // Clear session state
    memset(&session_state, 0, sizeof(session_state));
    
    printf("[fr_data] Module initialized\n");
    fflush(stdout);
    
    return FR_DATA_OK;
}

int fr_data_start_session(const char* filename) {
    if (!filename) {
        printf("[fr_data] ERROR: Invalid filename\n");
        fflush(stdout);
        return FR_DATA_INVALID_PARAM;
    }
    
    if (session_state.active) {
        printf("[fr_data] WARNING: Session already active, closing previous session\n");
        fflush(stdout);
        fr_data_end_session();
    }
    
    // Check if SD card is mounted
    if (!sd_is_mounted()) {
        printf("[fr_data] ERROR: SD card not mounted\n");
        fflush(stdout);
        return FR_DATA_STORAGE_ERROR;
    }
    
    // Check if file already exists
    if (sd_file_exists(filename)) {
        printf("[fr_data] WARNING: File %s already exists, will be overwritten\n", filename);
        fflush(stdout);
        // Delete existing file
        sd_delete_file(filename);
    }
    
    // Create new file with header
    const char header[] = "FR-DATA-GCM-v1\n";
    int result = sd_write_file(filename, (const uint8_t*)header, strlen(header));
    if (result != SD_OK) {
        printf("[fr_data] ERROR: Failed to create session file %s\n", filename);
        fflush(stdout);
        return FR_DATA_STORAGE_ERROR;
    }
    
    // Initialize session state
    strncpy(session_state.filename, filename, sizeof(session_state.filename) - 1);
    session_state.active = true;
    session_state.chunks_stored = 0;
    session_state.bytes_stored = strlen(header);
    
    printf("[fr_data] Session started: %s\n", filename);
    fflush(stdout);
    
    return FR_DATA_OK;
}

int fr_data_store_chunk(const uint8_t* data, size_t len, uint32_t seq) {
    if (!data || len == 0) {
        printf("[fr_data] ERROR: Invalid data or length\n");
        fflush(stdout);
        return FR_DATA_INVALID_PARAM;
    }
    
    if (!session_state.active) {
        printf("[fr_data] ERROR: No active session\n");
        fflush(stdout);
        return FR_DATA_NO_SESSION;
    }
    
    if (len > FR_DATA_MAX_CHUNK) {
        printf("[fr_data] ERROR: Chunk too large (%zu > %d)\n", len, FR_DATA_MAX_CHUNK);
        fflush(stdout);
        return FR_DATA_INVALID_PARAM;
    }
    
    printf("[fr_data] Storing chunk %u (%zu bytes)\n", seq, len);
    fflush(stdout);
    
    // Generate random IV for GCM
    uint8_t iv[FR_DATA_IV_SIZE];
    ATCA_STATUS status = generate_iv(iv);
    if (status != ATCA_SUCCESS) {
        printf("[fr_data] ERROR: Failed to generate IV: 0x%08X\n", status);
        fflush(stdout);
        return FR_DATA_CRYPTO_ERROR;
    }
    
    // Encrypt data using AES-GCM
    uint8_t ciphertext[FR_DATA_MAX_CHUNK];
    uint8_t tag[FR_DATA_TAG_SIZE];
    
    const uint8_t* aad = (const uint8_t*)FR_DATA_AAD;
    size_t aad_len = strlen(FR_DATA_AAD);
    
    status = aes_gcm_encrypt(
        SESSION_AES_SLOT,
        iv,
        FR_DATA_IV_SIZE,
        aad,
        aad_len,
        data,
        len,
        ciphertext,
        tag
    );
    
    if (status != ATCA_SUCCESS) {
        printf("[fr_data] ERROR: GCM encryption failed: 0x%08X\n", status);
        fflush(stdout);
        return FR_DATA_CRYPTO_ERROR;
    }
    
    printf("[fr_data] Chunk %u encrypted successfully\n", seq);
    fflush(stdout);
    
    // Prepare chunk header: [SEQ(4)] [LEN(4)] [IV(12)] [CIPHERTEXT(len)] [TAG(16)]
    // Use static buffer to avoid stack overflow (4132 bytes is too large for stack)
    static uint8_t chunk_buffer[8 + FR_DATA_IV_SIZE + FR_DATA_MAX_CHUNK + FR_DATA_TAG_SIZE];
    size_t offset = 0;
    
    // Sequence number (4 bytes, big-endian)
    chunk_buffer[offset++] = (seq >> 24) & 0xFF;
    chunk_buffer[offset++] = (seq >> 16) & 0xFF;
    chunk_buffer[offset++] = (seq >> 8) & 0xFF;
    chunk_buffer[offset++] = seq & 0xFF;
    
    // Plaintext length (4 bytes, big-endian)
    chunk_buffer[offset++] = (len >> 24) & 0xFF;
    chunk_buffer[offset++] = (len >> 16) & 0xFF;
    chunk_buffer[offset++] = (len >> 8) & 0xFF;
    chunk_buffer[offset++] = len & 0xFF;
    
    // IV
    memcpy(chunk_buffer + offset, iv, FR_DATA_IV_SIZE);
    offset += FR_DATA_IV_SIZE;
    
    // Ciphertext
    memcpy(chunk_buffer + offset, ciphertext, len);
    offset += len;
    
    // Tag
    memcpy(chunk_buffer + offset, tag, FR_DATA_TAG_SIZE);
    offset += FR_DATA_TAG_SIZE;
    
    // Append to SD card file
    int result = sd_append_file(session_state.filename, chunk_buffer, offset);
    if (result != SD_OK) {
        printf("[fr_data] ERROR: Failed to write chunk to SD card\n");
        fflush(stdout);
        return FR_DATA_STORAGE_ERROR;
    }
    
    // Update statistics
    session_state.chunks_stored++;
    session_state.bytes_stored += offset;
    
    printf("[fr_data] Chunk %u stored (%zu bytes total on disk)\n", seq, offset);
    fflush(stdout);
    
    return FR_DATA_OK;
}

int fr_data_end_session(void) {
    if (!session_state.active) {
        printf("[fr_data] WARNING: No active session to end\n");
        fflush(stdout);
        return FR_DATA_NO_SESSION;
    }
    
    printf("[fr_data] Session ended: %s\n", session_state.filename);
    printf("[fr_data] Total chunks: %u\n", session_state.chunks_stored);
    printf("[fr_data] Total bytes: %u\n", session_state.bytes_stored);
    fflush(stdout);
    
    // Clear session state
    memset(&session_state, 0, sizeof(session_state));
    
    return FR_DATA_OK;
}

bool fr_data_is_session_active(void) {
    return session_state.active;
}

const char* fr_data_get_session_filename(void) {
    if (!session_state.active) {
        return NULL;
    }
    return session_state.filename;
}

int fr_data_get_session_stats(uint32_t* chunks_stored, uint32_t* bytes_stored) {
    if (!chunks_stored || !bytes_stored) {
        return FR_DATA_INVALID_PARAM;
    }
    
    if (!session_state.active) {
        return FR_DATA_NO_SESSION;
    }
    
    *chunks_stored = session_state.chunks_stored;
    *bytes_stored = session_state.bytes_stored;
    
    return FR_DATA_OK;
}
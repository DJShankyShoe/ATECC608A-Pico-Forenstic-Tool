#include "http_upload.h"
#include "http_parse.h"
#include "sd_card.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char* buffer;
    size_t buffer_size;
    size_t received;
    size_t content_length;
    bool active;
    struct tcp_pcb* pcb;
    char boundary[128];
} upload_state_t;

static upload_state_t upload_state = {0};

bool http_upload_init(struct tcp_pcb* pcb, size_t content_length, const char* boundary) {
    if (upload_state.active) {
        printf("[Upload] Upload already in progress\n");
        return false;
    }

    if (content_length > MAX_UPLOAD_SIZE) {
        printf("[Upload] Too large: %zu bytes\n", content_length);
        return false;
    }

    upload_state.buffer = (char*)malloc(content_length);
    if (!upload_state.buffer) {
        printf("[Upload] Failed to allocate %zu bytes\n", content_length);
        return false;
    }

    upload_state.buffer_size = content_length;
    upload_state.received = 0;
    upload_state.content_length = content_length;
    upload_state.active = true;
    upload_state.pcb = pcb;
    
    if (boundary) {
        strncpy(upload_state.boundary, boundary, sizeof(upload_state.boundary) - 1);
        upload_state.boundary[sizeof(upload_state.boundary) - 1] = '\0';
    }

    printf("[Upload] Initialized: %zu bytes\n", content_length);
    return true;
}

bool http_upload_append_data(const char* data, size_t len) {
    if (!upload_state.active) {
        return false;
    }

    if (upload_state.received + len > upload_state.buffer_size) {
        printf("[Upload] Buffer overflow prevented\n");
        return false;
    }

    memcpy(upload_state.buffer + upload_state.received, data, len);
    upload_state.received += len;

    printf("[Upload] Received %zu/%zu bytes\n", upload_state.received, upload_state.content_length);
    
    return true;
}

bool http_upload_is_active(void) {
    return upload_state.active;
}

bool http_upload_process(char* filename_out, size_t filename_max) {
    if (!upload_state.active) {
        return false;
    }

    if (upload_state.received < upload_state.content_length) {
        printf("[Upload] Incomplete upload\n");
        return false;
    }

    char filename[128];
    uint8_t* file_data;
    size_t file_size;

    if (http_parse_multipart(upload_state.buffer, upload_state.received,
                            upload_state.boundary, filename, &file_data, &file_size) != 0) {
        printf("[Upload] Multipart parse failed\n");
        return false;
    }

    if (sd_write_file(filename, file_data, file_size) != SD_OK) {
        printf("[Upload] SD write failed\n");
        return false;
    }

    printf("[Upload] ✓ Saved: %s (%zu bytes)\n", filename, file_size);
    
    if (filename_out) {
        strncpy(filename_out, filename, filename_max - 1);
        filename_out[filename_max - 1] = '\0';
    }

    return true;
}

void http_upload_cleanup(void) {
    if (upload_state.buffer) {
        free(upload_state.buffer);
        upload_state.buffer = NULL;
    }
    upload_state.active = false;
    upload_state.received = 0;
    upload_state.content_length = 0;
    upload_state.buffer_size = 0;
    upload_state.pcb = NULL;
    upload_state.boundary[0] = '\0';
}

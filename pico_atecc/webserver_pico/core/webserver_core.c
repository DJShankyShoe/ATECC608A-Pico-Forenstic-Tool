#include "webserver_core.h"
#include "http_auth.h"
#include "http_parse.h"
#include "http_upload.h"
#include "http_response.h"
#include "sd_card.h"
#include "telem_decrypt_stream.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "lwip/pbuf.h"
#include "lwip/tcp.h"

static uint8_t file_buffer[MAX_FILE_SIZE_WEB];
static char html_buffer[HTML_BUFFER_SIZE];

// Download configuration
#define MAX_CHUNK_SIZE 1024  // Send file data in 1KB chunks

// Download state tracking
typedef struct {
    bool active;
    size_t total_size;
    size_t sent;
    size_t header_len;
    const uint8_t* file_data;  // Pointer to file data for chunked sending
    size_t file_offset;        // How much of file has been written to TCP
    bool is_streaming_telem;   // True if streaming telemetry decryption
    telem_stream_ctx_t* telem_ctx;  // Pointer to streaming context (malloc when needed)
    uint8_t chunk_buffer[4096];     // Buffer for one decrypted chunk
    size_t chunk_size;              // Size of current chunk
    size_t chunk_sent;              // How much of current chunk has been sent
    bool chunk_ready;               // True if chunk_buffer has decrypted data ready
} download_state_t;

static download_state_t download_state = {0};

static err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err);
static err_t tcp_server_sent(void *arg, struct tcp_pcb *tpcb, u16_t len);
static err_t tcp_server_accept(void *arg, struct tcp_pcb *newpcb, err_t err);

// Helper function to send file data in chunks
static void send_file_chunk(struct tcp_pcb *tpcb) {
    if (!download_state.active) {
        return;
    }
    
    // Get available TCP send buffer space
    u16_t available = tcp_sndbuf(tpcb);
    
    // Wait for at least 512 bytes of buffer space
    if (available < 512) {
        return;
    }
    
    // Handle streaming telemetry decryption
    if (download_state.is_streaming_telem && download_state.telem_ctx) {
        // Check if we need to decrypt next chunk
        if (!download_state.chunk_ready) {
            // Decrypt next chunk
            uint32_t seq;
            size_t decrypted_size;
            
            printf("[WebCore] Decrypting next chunk...\n");
            fflush(stdout);
            
            int result = telem_stream_decrypt_next(
                download_state.telem_ctx,
                download_state.chunk_buffer,
                &decrypted_size,
                &seq
            );
            
            if (result == TELEM_STREAM_END_OF_FILE) {
                // No more chunks
                printf("[WebCore] Stream end reached\n");
                fflush(stdout);
                return;
            } else if (result != TELEM_STREAM_OK) {
                printf("[WebCore] Decrypt failed: %d\n", result);
                fflush(stdout);
                download_state.active = false;
                if (download_state.telem_ctx) {
                    telem_stream_close(download_state.telem_ctx);
                    free(download_state.telem_ctx);
                    download_state.telem_ctx = NULL;
                }
                tcp_close(tpcb);
                return;
            }
            
            download_state.chunk_size = decrypted_size;
            download_state.chunk_sent = 0;
            download_state.chunk_ready = true;
            printf("[WebCore] Chunk %u ready: %zu bytes\n", seq, decrypted_size);
            fflush(stdout);
        }
        
        // Send from current decrypted chunk
        size_t remaining_in_chunk = download_state.chunk_size - download_state.chunk_sent;
        if (remaining_in_chunk == 0) {
            // Current chunk fully sent, mark as not ready
            download_state.chunk_ready = false;
            return;
        }
        
        u16_t to_send = remaining_in_chunk;
        if (to_send > available) {
            to_send = available;
        }
        if (to_send > MAX_CHUNK_SIZE) {
            to_send = MAX_CHUNK_SIZE;
        }
        
        err_t err = tcp_write(tpcb, 
                             download_state.chunk_buffer + download_state.chunk_sent,
                             to_send, 
                             TCP_WRITE_FLAG_COPY);
        
        if (err == ERR_OK) {
            download_state.chunk_sent += to_send;
            download_state.file_offset += to_send;  // Total bytes sent
            
            if (download_state.chunk_sent >= download_state.chunk_size) {
                download_state.chunk_ready = false;  // Need next chunk
            }
            
            tcp_output(tpcb);
        }
        
        return;
    }
    
    // Original logic for non-streaming files
    if (!download_state.file_data) {
        return;
    }
    
    size_t remaining = download_state.total_size - download_state.file_offset;
    if (remaining == 0) {
        return;
    }
    
    u16_t to_send = remaining;
    if (to_send > available) {
        to_send = available;
    }
    if (to_send > MAX_CHUNK_SIZE) {
        to_send = MAX_CHUNK_SIZE;
    }
    
    err_t err = tcp_write(tpcb, download_state.file_data + download_state.file_offset, 
                         to_send, TCP_WRITE_FLAG_COPY);
    
    if (err == ERR_OK) {
        download_state.file_offset += to_send;
        tcp_output(tpcb);
    }
}

static err_t tcp_server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    if (p == NULL) {
        http_upload_cleanup();
        if (download_state.is_streaming_telem && download_state.telem_ctx) {
            telem_stream_close(download_state.telem_ctx);
            free(download_state.telem_ctx);
            download_state.telem_ctx = NULL;
        }
        download_state.active = false;
        download_state.is_streaming_telem = false;
        download_state.file_data = NULL;
        tcp_close(tpcb);
        return ERR_OK;
    }

    char *request = (char *)p->payload;

    // Handle upload continuation
    if (http_upload_is_active()) {
        struct pbuf *q;
        for (q = p; q != NULL; q = q->next) {
            http_upload_append_data((char*)q->payload, q->len);
        }

        tcp_recved(tpcb, p->tot_len);
        pbuf_free(p);

        char filename[128];
        if (http_upload_process(filename, sizeof(filename))) {
            int len = http_response_upload_success(html_buffer, sizeof(html_buffer));
            tcp_write(tpcb, html_buffer, len, TCP_WRITE_FLAG_COPY);
            tcp_output(tpcb);
            http_upload_cleanup();
        }

        return ERR_OK;
    }

    // Parse method and path
    char method[16] = {0};
    char path[256] = {0};
    http_parse_method(request, method);
    http_parse_path(request, path, sizeof(path));
    printf("[WebCore] %s %s\n", method, path);

    // Check authorization
    if (!http_auth_check_request(request)) {
        int len = http_response_unauthorized(html_buffer, sizeof(html_buffer));
        tcp_write(tpcb, html_buffer, len, TCP_WRITE_FLAG_COPY);
        download_state.active = false;
    }
    // GET /
    else if (strncmp(request, "GET / ", 6) == 0 || strncmp(request, "GET /index", 10) == 0) {
        int len = http_response_homepage(html_buffer, sizeof(html_buffer));
        printf("[WebCore] Homepage size: %d bytes\n", len);
        
        // Use chunked sending for large homepage to avoid buffer overflow
        download_state.active = true;
        download_state.total_size = len;
        download_state.sent = 0;
        download_state.header_len = 0;  // No separate headers for homepage
        download_state.file_data = (const uint8_t*)html_buffer;
        download_state.file_offset = 0;
        
        // Start sending (will handle small or large automatically)
        send_file_chunk(tpcb);
    }
    // GET /download?file=...
    else if (strncmp(request, "GET /download?file=", 19) == 0) {
        char filename[128], decoded[128];
        const char* query = request + 19;
        int i = 0;

        while (query[i] != ' ' && query[i] != '&' && query[i] != '\r' && i < 127) {
            filename[i] = query[i];
            i++;
        }
        filename[i] = '\0';

        http_parse_url_decode(decoded, filename);
        printf("[WebCore] Download: %s\n", decoded);

        // Check if this is a telemetry file that needs decryption
        bool is_telem = telem_is_telemetry_file_quick(decoded);
        char download_filename[128];
        
        if (is_telem) {
            printf("[WebCore] Telemetry file - using streaming\n");
            fflush(stdout);
            
            // Allocate streaming context
            download_state.telem_ctx = (telem_stream_ctx_t*)malloc(sizeof(telem_stream_ctx_t));
            if (!download_state.telem_ctx) {
                printf("[WebCore] Failed to allocate streaming context\n");
                fflush(stdout);
                int len = http_response_error(html_buffer, sizeof(html_buffer), 
                                            "Out of memory");
                tcp_write(tpcb, html_buffer, len, TCP_WRITE_FLAG_COPY);
                tcp_output(tpcb);
                tcp_recved(tpcb, p->tot_len);
                pbuf_free(p);
                return ERR_OK;
            }
            
            // Open streaming context
            int result = telem_stream_open(download_state.telem_ctx, decoded);
            if (result != TELEM_STREAM_OK) {
                printf("[WebCore] Failed to open stream: %d\n", result);
                fflush(stdout);
                free(download_state.telem_ctx);
                download_state.telem_ctx = NULL;
                int len = http_response_error(html_buffer, sizeof(html_buffer), 
                                            "Failed to open telemetry file");
                tcp_write(tpcb, html_buffer, len, TCP_WRITE_FLAG_COPY);
                tcp_output(tpcb);
                tcp_recved(tpcb, p->tot_len);
                pbuf_free(p);
                return ERR_OK;
            }
            
            // Change filename for download (remove .dat, add .txt)
            strncpy(download_filename, decoded, sizeof(download_filename) - 1);
            char *dot = strrchr(download_filename, '.');
            if (dot && strcmp(dot, ".dat") == 0) {
                strcpy(dot, ".txt");
            }
            
            // Create response headers (no Content-Length for streaming)
            int header_len = snprintf(html_buffer, sizeof(html_buffer),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain; charset=UTF-8\r\n"
                "Content-Disposition: attachment; filename=\"%s\"\r\n"
                "Connection: close\r\n"
                "\r\n",
                download_filename);
            
            // Initialize download state for streaming
            download_state.active = true;
            download_state.is_streaming_telem = true;
            download_state.total_size = 0;  // Unknown until all chunks decrypted
            download_state.sent = 0;
            download_state.header_len = header_len;
            download_state.file_data = NULL;  // Not used for streaming
            download_state.file_offset = 0;
            download_state.chunk_size = 0;
            download_state.chunk_sent = 0;
            download_state.chunk_ready = false;
            
            // Send headers
            err_t err = tcp_write(tpcb, html_buffer, header_len, TCP_WRITE_FLAG_COPY);
            if (err != ERR_OK) {
                printf("[WebCore] Failed to write headers\n");
                fflush(stdout);
                telem_stream_close(download_state.telem_ctx);
                free(download_state.telem_ctx);
                download_state.telem_ctx = NULL;
                download_state.active = false;
            } else {
                tcp_output(tpcb);
                printf("[WebCore] Headers sent, ready to stream\n");
                fflush(stdout);
            }
        } else {
            // Regular file download (non-telemetry)
            int header_len = http_response_file_download(decoded, file_buffer, sizeof(file_buffer),
                                                        html_buffer, sizeof(html_buffer));

            if (header_len > 0) {
                size_t fsize = 0;
                sd_get_file_size(decoded, &fsize);
                
                // Initialize download state
                download_state.active = true;
                download_state.total_size = fsize;
                download_state.sent = 0;
                download_state.header_len = header_len;
                download_state.file_data = file_buffer;
                download_state.file_offset = 0;
                
                // Write headers only - file chunks will be sent after header ACK
                err_t err = tcp_write(tpcb, html_buffer, header_len, TCP_WRITE_FLAG_COPY);
                if (err != ERR_OK) {
                    printf("[WebCore] Failed to write headers: %d\n", err);
                    download_state.active = false;
                } else {
                    tcp_output(tpcb);
                    printf("[WebCore] Starting chunked download: %zu bytes\n", fsize);
                    // DON'T call send_file_chunk() here - wait for tcp_sent callback
                }
            } else {
                int len = http_response_not_found(html_buffer, sizeof(html_buffer));
                tcp_write(tpcb, html_buffer, len, TCP_WRITE_FLAG_COPY);
                download_state.active = false;
            }
        }
    }
    // GET /delete?file=...
    else if (strncmp(request, "GET /delete?file=", 17) == 0) {
        char filename[128], decoded[128];
        const char* query = request + 17;
        int i = 0;

        while (query[i] != ' ' && query[i] != '&' && query[i] != '\r' && i < 127) {
            filename[i] = query[i];
            i++;
        }
        filename[i] = '\0';

        http_parse_url_decode(decoded, filename);
        printf("[WebCore] Delete: %s\n", decoded);

        if (sd_is_mounted() && sd_file_exists(decoded) && sd_delete_file(decoded) == SD_OK) {
            int len = http_response_upload_success(html_buffer, sizeof(html_buffer));
            tcp_write(tpcb, html_buffer, len, TCP_WRITE_FLAG_COPY);
        } else {
            int len = http_response_error(html_buffer, sizeof(html_buffer), "Delete failed");
            tcp_write(tpcb, html_buffer, len, TCP_WRITE_FLAG_COPY);
        }
        download_state.active = false;
    }
    // POST /upload
    else if (strncmp(request, "POST /upload", 12) == 0) {
        download_state.active = false;
        if (!sd_is_mounted()) {
            int len = http_response_error(html_buffer, sizeof(html_buffer), "SD card not available");
            tcp_write(tpcb, html_buffer, len, TCP_WRITE_FLAG_COPY);
        } else {
            size_t content_length = http_parse_content_length(request);
            char boundary[128];

            if (http_parse_boundary(request, boundary, sizeof(boundary))) {
                if (http_upload_init(tpcb, content_length, boundary)) {
                    // Find body start
                    const char *body = strstr(request, "\r\n\r\n");
                    if (body) {
                        body += 4;
                        size_t header_size = body - request;
                        struct pbuf *q;
                        size_t offset = 0;

                        for (q = p; q != NULL; q = q->next) {
                            if (offset + q->len > header_size) {
                                size_t body_start = (offset < header_size) ? (header_size - offset) : 0;
                                size_t body_len = q->len - body_start;
                                http_upload_append_data((char*)q->payload + body_start, body_len);
                            }
                            offset += q->len;
                        }

                        char filename[128];
                        if (http_upload_process(filename, sizeof(filename))) {
                            int len = http_response_upload_success(html_buffer, sizeof(html_buffer));
                            tcp_write(tpcb, html_buffer, len, TCP_WRITE_FLAG_COPY);
                            http_upload_cleanup();
                        }
                    }
                }
            }
        }
    }
    else {
        int len = http_response_not_found(html_buffer, sizeof(html_buffer));
        tcp_write(tpcb, html_buffer, len, TCP_WRITE_FLAG_COPY);
        download_state.active = false;
    }

    tcp_output(tpcb);
    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);

    return ERR_OK;
}

static err_t tcp_server_sent(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    if (download_state.active) {
        download_state.sent += len;
        
        // Handle streaming telemetry
        if (download_state.is_streaming_telem && download_state.telem_ctx) {
            // Try to send more data
            send_file_chunk(tpcb);
            
            // Check if we're truly done - no chunk ready and can't get more
            if (!download_state.chunk_ready && download_state.chunk_sent >= download_state.chunk_size) {
                // Try to see if there's more
                uint32_t seq;
                size_t decrypted_size;
                int result = telem_stream_decrypt_next(
                    download_state.telem_ctx,
                    download_state.chunk_buffer,
                    &decrypted_size,
                    &seq
                );
                
                if (result == TELEM_STREAM_END_OF_FILE) {
                    // All done
                    printf("[WebCore] Stream complete, closing\n");
                    fflush(stdout);
                    telem_stream_close(download_state.telem_ctx);
                    free(download_state.telem_ctx);
                    download_state.telem_ctx = NULL;
                    download_state.active = false;
                    download_state.is_streaming_telem = false;
                    tcp_close(tpcb);
                } else if (result == TELEM_STREAM_OK) {
                    // Got next chunk
                    download_state.chunk_size = decrypted_size;
                    download_state.chunk_sent = 0;
                    download_state.chunk_ready = true;
                    // Will send in next call
                }
            }
        } else {
            // Original logic for non-streaming files
            if (download_state.file_offset < download_state.total_size) {
                send_file_chunk(tpcb);
            }
            
            if (download_state.file_offset >= download_state.total_size &&
                download_state.sent >= download_state.header_len + download_state.total_size) {
                printf("[WebCore] Download complete, closing\n");
                fflush(stdout);
                download_state.active = false;
                download_state.file_data = NULL;
                tcp_close(tpcb);
            }
        }
    } else {
        // For non-download responses, close immediately
        tcp_close(tpcb);
    }
    return ERR_OK;
}

static err_t tcp_server_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    tcp_recv(newpcb, tcp_server_recv);
    tcp_sent(newpcb, tcp_server_sent);
    return ERR_OK;
}

void webserver_core_start(uint16_t port) {
    struct tcp_pcb *pcb = tcp_new();
    if (!pcb) {
        printf("[WebCore] Failed to create PCB\n");
        return;
    }

    if (tcp_bind(pcb, IP_ADDR_ANY, port) != ERR_OK) {
        printf("[WebCore] Failed to bind\n");
        tcp_close(pcb);
        return;
    }

    pcb = tcp_listen(pcb);
    if (!pcb) {
        printf("[WebCore] Failed to listen\n");
        return;
    }

    tcp_accept(pcb, tcp_server_accept);
    printf("[WebCore] Server listening on port %d\n", port);
}
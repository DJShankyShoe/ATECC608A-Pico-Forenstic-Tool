#ifndef HTTP_UPLOAD_H
#define HTTP_UPLOAD_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include "lwip/tcp.h"

#define MAX_UPLOAD_SIZE 65536

bool http_upload_init(struct tcp_pcb* pcb, size_t content_length, const char* boundary);
bool http_upload_append_data(const char* data, size_t len);
bool http_upload_is_active(void);
bool http_upload_process(char* filename_out, size_t filename_max);
void http_upload_cleanup(void);

#endif

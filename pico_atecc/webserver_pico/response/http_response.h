#ifndef HTTP_RESPONSE_H
#define HTTP_RESPONSE_H

#include <stddef.h>
#include <stdint.h> 

#define HTML_BUFFER_SIZE 16384
#define MAX_FILE_SIZE_WEB 16384

int http_response_homepage(char* buffer, size_t buffer_size);
int http_response_file_download(const char* filename, uint8_t* file_buffer, size_t file_buffer_size, char* response_buffer, size_t response_buffer_size);
int http_response_unauthorized(char* buffer, size_t buffer_size);
int http_response_not_found(char* buffer, size_t buffer_size);
int http_response_upload_success(char* buffer, size_t buffer_size);
int http_response_error(char* buffer, size_t buffer_size, const char* error_msg);

#endif

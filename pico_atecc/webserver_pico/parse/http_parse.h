// http_parse.h - HTTP Request Parsing Module
#ifndef HTTP_PARSE_H
#define HTTP_PARSE_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

/**
 * URL decode a string (handles %XX encoding and + for spaces)
 * @param dst Destination buffer
 * @param src Source URL-encoded string
 */
void http_parse_url_decode(char* dst, const char* src);

/**
 * Extract Content-Length from HTTP request headers
 * @param request HTTP request string
 * @return Content length, or 0 if not found
 */
size_t http_parse_content_length(const char* request);

/**
 * Extract boundary string from Content-Type header
 * @param request HTTP request string
 * @param boundary Buffer to store boundary (should be at least 128 bytes)
 * @param max_len Maximum length of boundary buffer
 * @return true if boundary found, false otherwise
 */
bool http_parse_boundary(const char* request, char* boundary, size_t max_len);

/**
 * Extract filename from Content-Disposition header
 * @param header Header string containing Content-Disposition
 * @param filename Buffer to store filename
 * @param max_len Maximum length of filename buffer
 * @return true if filename extracted, false otherwise
 */
bool http_parse_filename(const char* header, char* filename, size_t max_len);

/**
 * Parse multipart form data and extract file content
 * @param data Multipart data
 * @param data_len Length of data
 * @param boundary Boundary string
 * @param filename Buffer to store extracted filename (128 bytes recommended)
 * @param file_data Pointer to store file data location (within data buffer)
 * @param file_size Pointer to store file size
 * @return 0 on success, -1 on error
 */
int http_parse_multipart(const char* data, size_t data_len, const char* boundary,
                         char* filename, uint8_t** file_data, size_t* file_size);

/**
 * Check if HTTP method matches
 * @param request HTTP request string
 * @param method Method to check (e.g., "GET", "POST")
 * @return true if method matches
 */
bool http_parse_method(const char* request, const char* method);

/**
 * Extract request path from HTTP request
 * @param request HTTP request string
 * @param path Buffer to store path
 * @param max_len Maximum length of path buffer
 * @return true if path extracted, false otherwise
 */
bool http_parse_path(const char* request, char* path, size_t max_len);

#endif // HTTP_PARSE_H

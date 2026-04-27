// http_auth.h - HTTP Basic Authentication Module
#ifndef HTTP_AUTH_H
#define HTTP_AUTH_H

#include <stdbool.h>
#include <stddef.h>

// ============================================================================
// CONFIGURATION
// ============================================================================

#define MAX_USERNAME_LEN 32
#define MAX_PASSWORD_LEN 32

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

/**
 * Set HTTP Basic Authentication credentials
 * @param username Username for authentication (NULL to disable)
 * @param password Password for authentication
 */
void http_auth_set_credentials(const char* username, const char* password);

/**
 * Disable HTTP Basic Authentication
 */
void http_auth_disable(void);

/**
 * Check if authentication is enabled
 * @return true if authentication is required, false otherwise
 */
bool http_auth_is_enabled(void);

/**
 * Check if HTTP request contains valid authorization credentials
 * @param request Full HTTP request string
 * @return true if authorized (or auth disabled), false if unauthorized
 */
bool http_auth_check_request(const char* request);

/**
 * Decode base64 string
 * @param input Base64 encoded string
 * @param output Buffer for decoded output
 * @param output_size Size of output buffer
 * @return Number of bytes decoded, or -1 on error
 */
int http_auth_base64_decode(const char* input, char* output, size_t output_size);

#endif // HTTP_AUTH_H

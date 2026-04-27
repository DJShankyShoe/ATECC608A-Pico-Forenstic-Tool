// http_auth.c - HTTP Basic Authentication Module Implementation
#include "http_auth.h"
#include <string.h>
#include <stdio.h>

// ============================================================================
// PRIVATE STATE
// ============================================================================

static bool auth_enabled = false;
static char auth_username[MAX_USERNAME_LEN] = {0};
static char auth_password[MAX_PASSWORD_LEN] = {0};

static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ============================================================================
// PUBLIC FUNCTIONS
// ============================================================================

void http_auth_set_credentials(const char* username, const char* password) {
    if (!username || !password) {
        http_auth_disable();
        return;
    }
    
    strncpy(auth_username, username, MAX_USERNAME_LEN - 1);
    auth_username[MAX_USERNAME_LEN - 1] = '\0';
    
    strncpy(auth_password, password, MAX_PASSWORD_LEN - 1);
    auth_password[MAX_PASSWORD_LEN - 1] = '\0';
    
    auth_enabled = true;
    
    printf("[HTTP Auth] Authentication enabled for user: %s\n", username);
}

void http_auth_disable(void) {
    auth_enabled = false;
    memset(auth_username, 0, sizeof(auth_username));
    memset(auth_password, 0, sizeof(auth_password));
    printf("[HTTP Auth] Authentication disabled\n");
}

bool http_auth_is_enabled(void) {
    return auth_enabled;
}

int http_auth_base64_decode(const char* input, char* output, size_t output_size) {
    int i = 0, j = 0;
    int len = strlen(input);
    unsigned char temp[4];
    
    while (i < len && j < output_size - 1) {
        int k;
        for (k = 0; k < 4 && i < len; k++, i++) {
            char c = input[i];
            if (c == '=') {
                temp[k] = 64;
            } else {
                const char* pos = strchr(base64_table, c);
                if (pos) {
                    temp[k] = pos - base64_table;
                } else {
                    return -1;  // Invalid character
                }
            }
        }
        
        if (k < 2) break;
        
        output[j++] = (temp[0] << 2) | (temp[1] >> 4);
        if (k > 2 && temp[2] != 64 && j < output_size - 1) {
            output[j++] = (temp[1] << 4) | (temp[2] >> 2);
        }
        if (k > 3 && temp[3] != 64 && j < output_size - 1) {
            output[j++] = (temp[2] << 6) | temp[3];
        }
    }
    
    output[j] = '\0';
    return j;
}

bool http_auth_check_request(const char* request) {
    // If auth not enabled, allow everything
    if (!auth_enabled) {
        return true;
    }
    
    // Look for Authorization header (case insensitive)
    const char* auth_header = strstr(request, "Authorization: Basic ");
    if (!auth_header) {
        auth_header = strstr(request, "authorization: basic ");
    }
    
    if (!auth_header) {
        printf("[HTTP Auth] No authorization header found\n");
        return false;
    }
    
    // Skip to the encoded credentials
    auth_header = strchr(auth_header, ' ') + 1;  // Skip "Authorization:"
    auth_header = strchr(auth_header, ' ') + 1;  // Skip "Basic"
    
    // Extract encoded credentials
    char encoded_creds[128];
    int i = 0;
    while (auth_header[i] != '\r' && auth_header[i] != '\n' && i < sizeof(encoded_creds) - 1) {
        encoded_creds[i] = auth_header[i];
        i++;
    }
    encoded_creds[i] = '\0';
    
    // Decode credentials
    char decoded_creds[128];
    if (http_auth_base64_decode(encoded_creds, decoded_creds, sizeof(decoded_creds)) < 0) {
        printf("[HTTP Auth] Base64 decode failed\n");
        return false;
    }
    
    // Split username:password
    char* colon = strchr(decoded_creds, ':');
    if (!colon) {
        printf("[HTTP Auth] Invalid credentials format\n");
        return false;
    }
    
    *colon = '\0';
    const char* username = decoded_creds;
    const char* password = colon + 1;
    
    // Check credentials
    bool authorized = (strcmp(username, auth_username) == 0 && strcmp(password, auth_password) == 0);
    
    if (authorized) {
        printf("[HTTP Auth] ✓ User '%s' authorized\n", username);
    } else {
        printf("[HTTP Auth] ✗ Invalid credentials for user '%s'\n", username);
    }
    
    return authorized;
}

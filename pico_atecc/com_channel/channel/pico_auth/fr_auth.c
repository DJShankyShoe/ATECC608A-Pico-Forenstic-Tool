#include "fr_auth.h"
#include "protocol.h"
#include "cert_signing.h"
#include "pico/stdlib.h"
#include <stdio.h>
#include <string.h>

bool fr_auth_handle_line(session_t* s, const char* line) {
    // Legacy host-supplied cert (optional sink for testing)
    if (strncmp(line, CMD_CERT_PREFIX, 5) == 0) {
        strncpy(s->cert, line + 5, sizeof(s->cert) - 1);
        s->have_cert = true;
        printf(REPLY_CERT_RECEIVED "\n");
        fflush(stdout);
        return true;
    }

    // Device presents its certificate when asked
    if (strcmp(line, CMD_CERT_REQ) == 0) {
        printf("[fr_auth] Certificate requested, generating...\n");
        
        // Generate self-signed certificate using Slot 0
        certificate_t cert;
        ATCA_STATUS status = cert_generate_self_signed(
            0,                  // Slot 0
            "PICO-TEAMIS18",   // Common Name
            "SIT",             // Organization
            "SG",              // Country
            &cert
        );
        
        if (status != ATCA_SUCCESS) {
            printf("[fr_auth] Certificate generation failed: 0x%08X\n", status);
            // Send error response
            printf(REPLY_CERT_RESP_PREFIX "ERROR:CERT_GEN_FAILED\n");
            fflush(stdout);
            return true;
        }
        
        printf("[fr_auth] Certificate generated (%zu bytes)\n", cert.der_length);
        
        // Convert to base64 using the cert_signing module function
        char cert_b64[2048];  // Large enough for typical cert
        bool success = cert_to_base64(&cert, cert_b64, sizeof(cert_b64));
        
        if (!success) {
            printf("[fr_auth] Failed to convert certificate to base64\n");
            cert_free(&cert);
            printf(REPLY_CERT_RESP_PREFIX "ERROR:BASE64_FAILED\n");
            fflush(stdout);
            return true;
        }
        
        // Store in session with X509CERT prefix
        snprintf(s->cert, sizeof(s->cert), "X509CERT:%s", cert_b64);
        s->have_cert = true;
        
        // Send certificate to host
        printf(REPLY_CERT_RESP_PREFIX "%s\n", s->cert);
        fflush(stdout);
        
        printf("[fr_auth] Certificate sent to host (base64 length: %zu)\n", strlen(cert_b64));
        
        // Free certificate memory
        cert_free(&cert);
        
        return true;
    }

    return false;
}
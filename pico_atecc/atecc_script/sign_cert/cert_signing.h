#ifndef CERT_SIGNING_H
#define CERT_SIGNING_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "cryptoauthlib.h"

#ifdef __cplusplus
extern "C" {
#endif

// Certificate structure to hold the generated certificate
typedef struct {
    uint8_t* der_data;      // DER-encoded certificate data
    size_t der_length;      // Length of DER data
    bool is_valid;          // Validity flag
} certificate_t;

// CSR (Certificate Signing Request) structure
typedef struct {
    uint8_t public_key[64];     // Extracted public key (X,Y coordinates)
    char common_name[128];      // CN from subject
    char organization[128];     // O from subject
    char country[8];            // C from subject
    bool is_valid;
} csr_info_t;

/**
 * @brief Generate a self-signed X.509 certificate
 */
ATCA_STATUS cert_generate_self_signed(uint16_t slot_id, 
                                      const char* common_name,
                                      const char* organization,
                                      const char* country,
                                      certificate_t* cert_out);

/**
 * @brief Parse a CSR from DER format
 */
bool cert_parse_csr(const uint8_t* csr_der, size_t csr_len, csr_info_t* csr_info);

/**
 * @brief Parse a CSR from PEM format
 */
bool cert_parse_csr_pem(const char* csr_pem, csr_info_t* csr_info);

/**
 * @brief Self-sign a CSR to create a certificate
 */
ATCA_STATUS cert_sign_csr(uint16_t slot_id,
                          const csr_info_t* csr_info,
                          const char* not_before,  // UTC time: "YYMMDDHHMMSSZ"
                          const char* not_after,   // UTC time: "YYMMDDHHMMSSZ"
                          certificate_t* cert_out);

/**
 * Free certificate memory
 */
void cert_free(certificate_t* cert);

/**
 * Print certificate in PEM format
 */
void cert_print_pem(const certificate_t* cert);

/**
 * Print certificate in hex format
 */
void cert_print_hex(const certificate_t* cert);

/**
 * Convert certificate to base64 string
 */
bool cert_to_base64(const certificate_t* cert, char* output, size_t output_size);

#ifdef __cplusplus
}
#endif

#endif
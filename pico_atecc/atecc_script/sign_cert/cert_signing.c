#include "cert_signing.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pico/stdlib.h"

// ASN.1 DER tags
#define ASN1_BOOLEAN           0x01
#define ASN1_INTEGER           0x02
#define ASN1_BIT_STRING        0x03
#define ASN1_OCTET_STRING      0x04
#define ASN1_NULL              0x05
#define ASN1_OID               0x06
#define ASN1_UTF8_STRING       0x0C
#define ASN1_PRINTABLE_STRING  0x13
#define ASN1_UTC_TIME          0x17
#define ASN1_SEQUENCE          0x30
#define ASN1_SET               0x31
#define ASN1_CONTEXT_SPECIFIC  0xA0

// OIDs
static const uint8_t OID_EC_PUBLIC_KEY[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01};
static const uint8_t OID_SECP256R1[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07};
static const uint8_t OID_ECDSA_WITH_SHA256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02};
static const uint8_t OID_COMMON_NAME[] = {0x55, 0x04, 0x03};
static const uint8_t OID_ORGANIZATION[] = {0x55, 0x04, 0x0A};
static const uint8_t OID_COUNTRY[] = {0x55, 0x04, 0x06};

// Extension OIDs
static const uint8_t OID_BASIC_CONSTRAINTS[] = {0x55, 0x1D, 0x13};
static const uint8_t OID_KEY_USAGE[] = {0x55, 0x1D, 0x0F};
static const uint8_t OID_EXT_KEY_USAGE[] = {0x55, 0x1D, 0x25};
static const uint8_t OID_SUBJECT_ALT_NAME[] = {0x55, 0x1D, 0x11};
static const uint8_t OID_SERVER_AUTH[] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01};

// Base64 decode table
static const uint8_t base64_decode_table[256] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x3E, 0xFF, 0xFF, 0xFF, 0x3F,
    0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF,
    0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
    0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
    0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

// DER parsing helpers
static size_t der_get_length(const uint8_t** p) {
    size_t len = **p;
    (*p)++;
    
    if (len & 0x80) {
        size_t num_bytes = len & 0x7F;
        len = 0;
        for (size_t i = 0; i < num_bytes; i++) {
            len = (len << 8) | **p;
            (*p)++;
        }
    }
    return len;
}

// Skip expected tag and length, return true if successful
static bool der_skip_tag_length(const uint8_t** p, const uint8_t* end, uint8_t expected_tag) {
    if (*p >= end || **p != expected_tag) return false;
    (*p)++;
    size_t len = der_get_length(p);
    if (*p + len > end) return false;
    return true;
}

// Parse and verify OID, return true if matches expected
static bool der_parse_oid(const uint8_t** p, const uint8_t* end, const uint8_t* expected_oid, size_t oid_len) {
    if (*p >= end || **p != ASN1_OID) return false;
    (*p)++;
    size_t len = der_get_length(p);
    if (len != oid_len || *p + len > end) return false;
    bool match = memcmp(*p, expected_oid, oid_len) == 0;
    *p += len;
    return match;
}

// DER encoding helpers
static uint8_t* der_encode_length(uint8_t* p, size_t len) {
    if (len < 128) {
        *p++ = (uint8_t)len;
    } else if (len < 256) {
        *p++ = 0x81;
        *p++ = (uint8_t)len;
    } else {
        *p++ = 0x82;
        *p++ = (uint8_t)(len >> 8);
        *p++ = (uint8_t)len;
    }
    return p;
}

// Encode tag and length
static uint8_t* der_encode_tag_length(uint8_t* p, uint8_t tag, size_t len) {
    *p++ = tag;
    return der_encode_length(p, len);
}

// Encode an INTEGER value
static uint8_t* der_encode_integer(uint8_t* p, const uint8_t* data, size_t len) {
    // Skip leading zeros
    while (len > 0 && *data == 0) {
        data++;
        len--;
    }
    
    // Add padding byte if MSB is set
    bool need_padding = (len > 0 && (*data & 0x80));
    
    p = der_encode_tag_length(p, ASN1_INTEGER, need_padding ? len + 1 : len);
    if (need_padding) *p++ = 0x00;
    memcpy(p, data, len);
    return p + len;
}

// Encode an OBJECT IDENTIFIER
static uint8_t* der_encode_oid(uint8_t* p, const uint8_t* oid, size_t len) {
    p = der_encode_tag_length(p, ASN1_OID, len);
    memcpy(p, oid, len);
    return p + len;
}

// Encode a PrintableString
static uint8_t* der_encode_string(uint8_t* p, uint8_t tag, const char* str) {
    size_t len = strlen(str);
    p = der_encode_tag_length(p, tag, len);
    memcpy(p, str, len);
    return p + len;
}

// Encode UTC Time
static uint8_t* der_encode_utc_time(uint8_t* p, const char* time_str) {
    p = der_encode_tag_length(p, ASN1_UTC_TIME, 13);
    memcpy(p, time_str, 13);
    return p + 13;
}

// Build X.509 Name (DN)
static size_t build_name(uint8_t* buf, const char* cn, const char* org, const char* country) {
    uint8_t* p = buf;
    uint8_t* seq_start = p;
    
    p++; // Tag
    uint8_t* len_pos = p;
    p++; // Length placeholder
    
    // CN
    if (cn && strlen(cn) > 0) {
        *p++ = ASN1_SET;
        uint8_t* set_len = p++;
        *p++ = ASN1_SEQUENCE;
        uint8_t* seq_len = p++;
        
        p = der_encode_oid(p, OID_COMMON_NAME, sizeof(OID_COMMON_NAME));
        p = der_encode_string(p, ASN1_PRINTABLE_STRING, cn);
        
        *seq_len = p - seq_len - 1;
        *set_len = p - set_len - 1;
    }
    
    // Organization
    if (org && strlen(org) > 0) {
        *p++ = ASN1_SET;
        uint8_t* set_len = p++;
        *p++ = ASN1_SEQUENCE;
        uint8_t* seq_len = p++;
        
        p = der_encode_oid(p, OID_ORGANIZATION, sizeof(OID_ORGANIZATION));
        p = der_encode_string(p, ASN1_PRINTABLE_STRING, org);
        
        *seq_len = p - seq_len - 1;
        *set_len = p - set_len - 1;
    }
    
    // Country
    if (country && strlen(country) > 0) {
        *p++ = ASN1_SET;
        uint8_t* set_len = p++;
        *p++ = ASN1_SEQUENCE;
        uint8_t* seq_len = p++;
        
        p = der_encode_oid(p, OID_COUNTRY, sizeof(OID_COUNTRY));
        p = der_encode_string(p, ASN1_PRINTABLE_STRING, country);
        
        *seq_len = p - seq_len - 1;
        *set_len = p - set_len - 1;
    }
    
    *seq_start = ASN1_SEQUENCE;
    *len_pos = p - len_pos - 1;
    
    return p - buf;
}

// Build SubjectPublicKeyInfo
static size_t build_subject_public_key_info(uint8_t* buf, const uint8_t* public_key) {
    uint8_t* p = buf;
    uint8_t* seq_start = p;
    
    p++; // Tag
    uint8_t* seq_len = p++;
    
    // Algorithm Identifier
    *p++ = ASN1_SEQUENCE;
    uint8_t* alg_len = p++;
    p = der_encode_oid(p, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY));
    p = der_encode_oid(p, OID_SECP256R1, sizeof(OID_SECP256R1));
    *alg_len = p - alg_len - 1;
    
    // Public Key (BIT STRING)
    *p++ = ASN1_BIT_STRING;
    *p++ = 66; // 1 (unused bits) + 1 (0x04) + 64 (key data)
    *p++ = 0x00; // No padding
    *p++ = 0x04; // Uncompressed point
    memcpy(p, public_key, 64);
    p += 64;
    
    *seq_start = ASN1_SEQUENCE;
    *seq_len = p - seq_len - 1;
    
    return p - buf;
}

// SHA-256 using ATECC608
static void sha256_atca(const uint8_t* data, size_t len, uint8_t* hash) {
    ATCA_STATUS status = atcab_sha(len, data, hash);
    
    if (status != ATCA_SUCCESS) {
        // Fallback: use start/update/end
        atcab_sha_start();
        
        size_t remaining = len;
        const uint8_t* p = data;
        
        while (remaining >= 64) {
            atcab_sha_update(p);
            p += 64;
            remaining -= 64;
        }
        
        atcab_sha_end(hash, remaining, p);
    }
}

// Build X.509 v3 Extensions
static size_t build_extensions(uint8_t* buf, const char* cn) {
    uint8_t* p = buf;
    uint8_t* ext_start = p;
    
    // Extensions [3] EXPLICIT
    *p++ = ASN1_CONTEXT_SPECIFIC | 0x03;
    uint8_t* ext_ctx_len = p++;
    
    // SEQUENCE OF Extension
    *p++ = ASN1_SEQUENCE;
    uint8_t* ext_seq_len = p++;
    
    // Extension 1: basicConstraints (CA=FALSE)
    {
        *p++ = ASN1_SEQUENCE;
        uint8_t* bc_len = p++;
        
        p = der_encode_oid(p, OID_BASIC_CONSTRAINTS, sizeof(OID_BASIC_CONSTRAINTS));
        
        // extnValue OCTET STRING
        *p++ = ASN1_OCTET_STRING;
        *p++ = 2;  // Length of inner SEQUENCE
        *p++ = ASN1_SEQUENCE;
        *p++ = 0;  // Empty sequence (CA=FALSE is default)
        
        *bc_len = p - bc_len - 1;
    }
    
    // Extension 2: keyUsage (digitalSignature)
    {
        *p++ = ASN1_SEQUENCE;
        uint8_t* ku_len = p++;
        
        p = der_encode_oid(p, OID_KEY_USAGE, sizeof(OID_KEY_USAGE));
        
        *p++ = ASN1_BOOLEAN;  // critical
        *p++ = 1;
        *p++ = 0xFF;
        
        // extnValue OCTET STRING
        *p++ = ASN1_OCTET_STRING;
        *p++ = 4;  // Length of BIT STRING
        *p++ = ASN1_BIT_STRING;
        *p++ = 2;  // Length
        *p++ = 7;  // Unused bits
        *p++ = 0x80;  // digitalSignature bit
        
        *ku_len = p - ku_len - 1;
    }
    
    // Extension 3: extendedKeyUsage (serverAuth)
    {
        *p++ = ASN1_SEQUENCE;
        uint8_t* eku_len = p++;
        
        p = der_encode_oid(p, OID_EXT_KEY_USAGE, sizeof(OID_EXT_KEY_USAGE));
        
        // extnValue OCTET STRING
        *p++ = ASN1_OCTET_STRING;
        uint8_t* eku_val_len = p++;
        
        *p++ = ASN1_SEQUENCE;
        uint8_t* eku_seq_len = p++;
        p = der_encode_oid(p, OID_SERVER_AUTH, sizeof(OID_SERVER_AUTH));
        *eku_seq_len = p - eku_seq_len - 1;
        
        *eku_val_len = p - eku_val_len - 1;
        *eku_len = p - eku_len - 1;
    }
    
    // Extension 4: subjectAltName (dNSName)
    if (cn && strlen(cn) > 0) {
        *p++ = ASN1_SEQUENCE;
        uint8_t* san_len = p++;
        
        p = der_encode_oid(p, OID_SUBJECT_ALT_NAME, sizeof(OID_SUBJECT_ALT_NAME));
        
        // extnValue OCTET STRING
        *p++ = ASN1_OCTET_STRING;
        uint8_t* san_val_len = p++;
        
        *p++ = ASN1_SEQUENCE;
        uint8_t* san_seq_len = p++;
        
        // dNSName [2] IMPLICIT IA5String
        *p++ = 0x82;  // context-specific [2]
        size_t cn_len = strlen(cn);
        *p++ = cn_len;
        memcpy(p, cn, cn_len);
        p += cn_len;
        
        *san_seq_len = p - san_seq_len - 1;
        *san_val_len = p - san_val_len - 1;
        *san_len = p - san_len - 1;
    }
    
    *ext_seq_len = p - ext_seq_len - 1;
    *ext_ctx_len = p - ext_ctx_len - 1;
    
    return p - ext_start;
}

// Parse CSR from DER format
bool cert_parse_csr(const uint8_t* csr_der, size_t csr_len, csr_info_t* csr_info) {
    if (!csr_der || !csr_info) return false;
    
    memset(csr_info, 0, sizeof(csr_info_t));
    
    const uint8_t* p = csr_der;
    const uint8_t* end = csr_der + csr_len;
    
    // CertificationRequest SEQUENCE
    if (!der_skip_tag_length(&p, end, ASN1_SEQUENCE)) {
        printf("[CSR] Failed to parse outer SEQUENCE\n");
        return false;
    }
    
    // CertificationRequestInfo SEQUENCE
    if (*p != ASN1_SEQUENCE) {
        printf("[CSR] Expected CertificationRequestInfo SEQUENCE\n");
        return false;
    }
    p++;
    der_get_length(&p);  // Skip length
    
    // Version
    if (*p != ASN1_INTEGER) {
        printf("[CSR] Expected version INTEGER\n");
        return false;
    }
    p++;
    size_t ver_len = der_get_length(&p);
    p += ver_len;
    
    // Subject Name SEQUENCE
    if (*p != ASN1_SEQUENCE) {
        printf("[CSR] Expected subject SEQUENCE\n");
        return false;
    }
    p++;
    size_t subject_len = der_get_length(&p);
    const uint8_t* subject_end = p + subject_len;
    
    // Parse subject RDNs
    while (p < subject_end) {
        if (*p != ASN1_SET) break;
        p++;
        size_t set_len = der_get_length(&p);
        const uint8_t* set_end = p + set_len;
        
        if (*p != ASN1_SEQUENCE) {
            p = set_end;
            continue;
        }
        p++;
        der_get_length(&p);  // Skip sequence length
        
        if (*p != ASN1_OID) {
            p = set_end;
            continue;
        }
        p++;
        size_t oid_len = der_get_length(&p);
        const uint8_t* oid = p;
        p += oid_len;
        
        // Get string value
        p++;  // Skip string tag
        size_t str_len = der_get_length(&p);
        
        if (oid_len == sizeof(OID_COMMON_NAME) && memcmp(oid, OID_COMMON_NAME, oid_len) == 0) {
            if (str_len < sizeof(csr_info->common_name)) {
                memcpy(csr_info->common_name, p, str_len);
                csr_info->common_name[str_len] = '\0';
            }
        } else if (oid_len == sizeof(OID_ORGANIZATION) && memcmp(oid, OID_ORGANIZATION, oid_len) == 0) {
            if (str_len < sizeof(csr_info->organization)) {
                memcpy(csr_info->organization, p, str_len);
                csr_info->organization[str_len] = '\0';
            }
        } else if (oid_len == sizeof(OID_COUNTRY) && memcmp(oid, OID_COUNTRY, oid_len) == 0) {
            if (str_len < sizeof(csr_info->country)) {
                memcpy(csr_info->country, p, str_len);
                csr_info->country[str_len] = '\0';
            }
        }
        
        p += str_len;
    }
    
    p = subject_end;
    
    // SubjectPublicKeyInfo SEQUENCE
    if (*p != ASN1_SEQUENCE) {
        printf("[CSR] Expected SubjectPublicKeyInfo SEQUENCE\n");
        return false;
    }
    p++;
    der_get_length(&p);  // Skip SPKI length
    
    // Algorithm SEQUENCE
    if (*p != ASN1_SEQUENCE) {
        printf("[CSR] Expected algorithm SEQUENCE\n");
        return false;
    }
    p++;
    size_t alg_len = der_get_length(&p);
    const uint8_t* alg_end = p + alg_len;
    
    // Verify EC public key OID
    if (!der_parse_oid(&p, alg_end, OID_EC_PUBLIC_KEY, sizeof(OID_EC_PUBLIC_KEY))) {
        printf("[CSR] Not an EC public key\n");
        return false;
    }
    
    // Verify secp256r1 OID
    if (!der_parse_oid(&p, alg_end, OID_SECP256R1, sizeof(OID_SECP256R1))) {
        printf("[CSR] Not secp256r1 curve\n");
        return false;
    }
    
    p = alg_end;
    
    // Public key BIT STRING
    if (*p != ASN1_BIT_STRING) {
        printf("[CSR] Expected public key BIT STRING\n");
        return false;
    }
    p++;
    size_t pk_len = der_get_length(&p);
    
    if (*p != 0x00) {
        printf("[CSR] Invalid bit string padding\n");
        return false;
    }
    p++; // Skip padding byte
    pk_len--;
    
    if (*p != 0x04) {
        printf("[CSR] Expected uncompressed EC point (0x04)\n");
        return false;
    }
    p++;
    pk_len--;
    
    if (pk_len != 64) {
        printf("[CSR] Invalid EC point length: %zu (expected 64)\n", pk_len);
        return false;
    }
    
    memcpy(csr_info->public_key, p, 64);
    csr_info->is_valid = true;
    
    printf("[CSR] Parsed successfully:\n");
    printf("  CN: %s\n", csr_info->common_name);
    printf("  O: %s\n", csr_info->organization);
    printf("  C: %s\n", csr_info->country);
    printf("  Public Key X: ");
    for (int i = 0; i < 32; i++) printf("%02X", csr_info->public_key[i]);
    printf("\n");
    printf("  Public Key Y: ");
    for (int i = 32; i < 64; i++) printf("%02X", csr_info->public_key[i]);
    printf("\n");
    
    return true;
}

// Parse CSR from PEM format
bool cert_parse_csr_pem(const char* csr_pem, csr_info_t* csr_info) {
    if (!csr_pem || !csr_info) return false;
    
    // Find BEGIN and END markers
    const char* begin = strstr(csr_pem, "-----BEGIN CERTIFICATE REQUEST-----");
    if (!begin) {
        printf("[CSR] BEGIN marker not found\n");
        return false;
    }
    begin += strlen("-----BEGIN CERTIFICATE REQUEST-----");
    
    const char* end = strstr(begin, "-----END CERTIFICATE REQUEST-----");
    if (!end) {
        printf("[CSR] END marker not found\n");
        return false;
    }
    
    // Decode base64
    uint8_t der_buffer[1024];
    size_t der_len = 0;
    uint32_t val = 0;
    int bits = 0;
    
    while (begin < end) {
        char c = *begin++;
        
        // Skip whitespace
        if (c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
        
        // Handle padding
        if (c == '=') {
            bits = 0;
            break;
        }
        
        uint8_t decoded = base64_decode_table[(uint8_t)c];
        if (decoded == 0xFF) continue; // Invalid char
        
        val = (val << 6) | decoded;
        bits += 6;
        
        if (bits >= 8) {
            bits -= 8;
            der_buffer[der_len++] = (val >> bits) & 0xFF;
            val &= (1 << bits) - 1;
            
            if (der_len >= sizeof(der_buffer)) {
                printf("[CSR] DER buffer overflow\n");
                return false;
            }
        }
    }
    
    printf("[CSR] Decoded %zu bytes from PEM\n", der_len);
    
    return cert_parse_csr(der_buffer, der_len, csr_info);
}

// Self-sign a CSR
ATCA_STATUS cert_sign_csr(uint16_t slot_id,
                          const csr_info_t* csr_info,
                          const char* not_before,
                          const char* not_after,
                          certificate_t* cert_out)
{
    if (!csr_info || !csr_info->is_valid || !cert_out || !not_before || !not_after) {
        return ATCA_BAD_PARAM;
    }
    
    ATCA_STATUS status;
    
    // Initialize output
    cert_out->der_data = NULL;
    cert_out->der_length = 0;
    cert_out->is_valid = false;
    
    // Verify that the public key in the slot matches the CSR
    uint8_t slot_public_key[64];
    status = atcab_get_pubkey(slot_id, slot_public_key);
    if (status != ATCA_SUCCESS) {
        printf("[cert] Failed to get public key from slot %d: 0x%08X\n", slot_id, status);
        return status;
    }
    
    if (memcmp(slot_public_key, csr_info->public_key, 64) != 0) {
        printf("[cert] WARNING: Public key in slot %d doesn't match CSR!\n", slot_id);
        printf("  Slot key X: ");
        for (int i = 0; i < 32; i++) printf("%02X", slot_public_key[i]);
        printf("\n");
        printf("  Slot key Y: ");
        for (int i = 32; i < 64; i++) printf("%02X", slot_public_key[i]);
        printf("\n");
        printf("  CSR key X:  ");
        for (int i = 0; i < 32; i++) printf("%02X", csr_info->public_key[i]);
        printf("\n");
        printf("  CSR key Y:  ");
        for (int i = 32; i < 64; i++) printf("%02X", csr_info->public_key[i]);
        printf("\n");
        // Continue anyway but warn user
    }
    
    // Build TBSCertificate
    uint8_t tbs_cert[768];
    uint8_t* p = tbs_cert;
    uint8_t* tbs_start = p;
    
    *p++ = ASN1_SEQUENCE; // Write sequence tag
    uint8_t* tbs_len_pos = p;
    p += 3; // Reserve 3 bytes for 0x82 HH LL
    
    // Version [0] EXPLICIT v3
    *p++ = ASN1_CONTEXT_SPECIFIC | 0;
    *p++ = 3;
    *p++ = ASN1_INTEGER;
    *p++ = 1;
    *p++ = 2; // v3
    
    // Serial Number (random) - ATECC returns 32 bytes
    uint8_t serial[32] = {0};
    atcab_random(serial);
    p = der_encode_integer(p, serial, 32);
    
    // Signature Algorithm
    *p++ = ASN1_SEQUENCE;
    *p++ = sizeof(OID_ECDSA_WITH_SHA256) + 2;
    p = der_encode_oid(p, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256));
    
    // Issuer (same as Subject for self-signed)
    size_t issuer_len = build_name(p, csr_info->common_name, csr_info->organization, csr_info->country);
    p += issuer_len;
    
    // Validity
    *p++ = ASN1_SEQUENCE;
    *p++ = 30; // 2 * 13 + 4
    p = der_encode_utc_time(p, not_before);
    p = der_encode_utc_time(p, not_after);
    
    // Subject (from CSR)
    size_t subject_len = build_name(p, csr_info->common_name, csr_info->organization, csr_info->country);
    p += subject_len;
    
    // SubjectPublicKeyInfo (from CSR)
    size_t spki_len = build_subject_public_key_info(p, csr_info->public_key);
    p += spki_len;
    
    // Extensions [3] EXPLICIT (v3)
    size_t ext_len = build_extensions(p, csr_info->common_name);
    p += ext_len;
    
    // Update TBS length
    size_t tbs_len = p - tbs_start - 4;  // -4 for tag + 3-byte length
    tbs_len_pos[0] = 0x82;
    tbs_len_pos[1] = (tbs_len >> 8) & 0xFF;
    tbs_len_pos[2] = tbs_len & 0xFF;
    
    size_t tbs_total_len = p - tbs_start;
    
    // Hash TBSCertificate
    uint8_t tbs_hash[32];
    sha256_atca(tbs_start, tbs_total_len, tbs_hash);
    
    printf("[cert] TBS Hash: ");
    for (int i = 0; i < 32; i++) printf("%02X", tbs_hash[i]);
    printf("\n");
    
    // Sign with slot
    uint8_t signature[64];
    status = atcab_sign(slot_id, tbs_hash, signature);
    if (status != ATCA_SUCCESS) {
        printf("[cert] Sign failed: 0x%08X\n", status);
        return status;
    }
    
    // Build final certificate
    uint8_t* cert = malloc(1024);
    if (!cert) {
        return ATCA_ALLOC_FAILURE;
    }
    
    uint8_t* c = cert;
    uint8_t* cert_start = c;
    
    *c++ = ASN1_SEQUENCE; // Write sequence tag
    uint8_t* cert_len_pos = c;
    c += 3; // Reserve 3 bytes for 0x82 HH LL
    
    // TBSCertificate
    memcpy(c, tbs_start, tbs_total_len);
    c += tbs_total_len;
    
    // SignatureAlgorithm
    *c++ = ASN1_SEQUENCE;
    *c++ = sizeof(OID_ECDSA_WITH_SHA256) + 2;
    c = der_encode_oid(c, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256));
    
    // SignatureValue (BIT STRING with DER-encoded ECDSA signature)
    uint8_t sig_der[72];
    uint8_t* s = sig_der;
    *s++ = ASN1_SEQUENCE;
    uint8_t* sig_len_pos = s++;
    s = der_encode_integer(s, signature, 32); // R
    s = der_encode_integer(s, signature + 32, 32); // S
    *sig_len_pos = s - sig_len_pos - 1;
    size_t sig_der_len = s - sig_der;
    
    *c++ = ASN1_BIT_STRING;
    *c++ = sig_der_len + 1;
    *c++ = 0x00; // No padding
    memcpy(c, sig_der, sig_der_len);
    c += sig_der_len;
    
    // Update certificate length
    size_t cert_len = c - cert_start - 4;  // -4 for tag + 3-byte length
    cert_len_pos[0] = 0x82;
    cert_len_pos[1] = (cert_len >> 8) & 0xFF;
    cert_len_pos[2] = cert_len & 0xFF;
    
    size_t cert_total_len = c - cert_start;
    
    // Store in output structure
    cert_out->der_data = cert;
    cert_out->der_length = cert_total_len;
    cert_out->is_valid = true;
    
    printf("[cert] Certificate signed successfully (%zu bytes)\n", cert_total_len);
    
    return ATCA_SUCCESS;
}

// Generate a self-signed certificate
ATCA_STATUS cert_generate_self_signed(uint16_t slot_id, 
                                      const char* common_name,
                                      const char* organization,
                                      const char* country,
                                      certificate_t* cert_out)
{
    if (!cert_out || !common_name) {
        return ATCA_BAD_PARAM;
    }
    
    ATCA_STATUS status;
    
    // Initialize output
    cert_out->der_data = NULL;
    cert_out->der_length = 0;
    cert_out->is_valid = false;
    
    // Get or generate public key
    uint8_t public_key[64];
    status = atcab_get_pubkey(slot_id, public_key);
    if (status != ATCA_SUCCESS) {
        printf("[cert] No key in Slot %d, generating...\n", slot_id);
        status = atcab_genkey(slot_id, NULL);
        if (status != ATCA_SUCCESS) {
            printf("[cert] GenKey failed: 0x%08X\n", status);
            return status;
        }
        status = atcab_get_pubkey(slot_id, public_key);
        if (status != ATCA_SUCCESS) {
            printf("[cert] Get pubkey failed: 0x%08X\n", status);
            return status;
        }
    }
    
    // Build TBSCertificate
    uint8_t tbs_cert[768];
    uint8_t* p = tbs_cert;
    uint8_t* tbs_start = p;
    
    *p++ = ASN1_SEQUENCE; // Write sequence tag
    uint8_t* tbs_len_pos = p;
    p += 3; // Reserve 3 bytes for 0x82 HH LL
    
    // Version [0] EXPLICIT v3
    *p++ = ASN1_CONTEXT_SPECIFIC | 0;
    *p++ = 3;
    *p++ = ASN1_INTEGER;
    *p++ = 1;
    *p++ = 2; // v3
    
    // Serial Number (random) - ATECC returns 32 bytes
    uint8_t serial[32] = {0};
    atcab_random(serial);
    p = der_encode_integer(p, serial, 32);
    
    // Signature Algorithm
    *p++ = ASN1_SEQUENCE;
    *p++ = sizeof(OID_ECDSA_WITH_SHA256) + 2;
    p = der_encode_oid(p, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256));
    
    // Issuer (same as Subject for self-signed)
    size_t issuer_len = build_name(p, common_name, organization, country);
    p += issuer_len;
    
    // Validity
    *p++ = ASN1_SEQUENCE;
    *p++ = 30; // 2 * 13 + 4
    p = der_encode_utc_time(p, "250101000000Z"); // notBefore
    p = der_encode_utc_time(p, "350101000000Z"); // notAfter
    
    // Subject (same as Issuer)
    size_t subject_len = build_name(p, common_name, organization, country);
    p += subject_len;
    
    // SubjectPublicKeyInfo
    size_t spki_len = build_subject_public_key_info(p, public_key);
    p += spki_len;
    
    // Extensions [3] EXPLICIT (v3)
    size_t ext_len = build_extensions(p, common_name);
    p += ext_len;
    
    // Update TBS length
    size_t tbs_len = p - tbs_start - 4;  // -4 for tag + 3-byte length
    tbs_len_pos[0] = 0x82;
    tbs_len_pos[1] = (tbs_len >> 8) & 0xFF;
    tbs_len_pos[2] = tbs_len & 0xFF;
    
    size_t tbs_total_len = p - tbs_start;
    
    // Hash TBSCertificate
    uint8_t tbs_hash[32];
    sha256_atca(tbs_start, tbs_total_len, tbs_hash);
    
    // Sign with slot
    uint8_t signature[64];
    status = atcab_sign(slot_id, tbs_hash, signature);
    if (status != ATCA_SUCCESS) {
        printf("[cert] Sign failed: 0x%08X\n", status);
        return status;
    }
    
    // Build final certificate
    uint8_t* cert = malloc(1024);
    if (!cert) {
        return ATCA_ALLOC_FAILURE;
    }
    
    uint8_t* c = cert;
    uint8_t* cert_start = c;
    
    *c++ = ASN1_SEQUENCE; // Write sequence tag
    uint8_t* cert_len_pos = c;
    c += 3; // Reserve 3 bytes for 0x82 HH LL
    
    // TBSCertificate
    memcpy(c, tbs_start, tbs_total_len);
    c += tbs_total_len;
    
    // SignatureAlgorithm
    *c++ = ASN1_SEQUENCE;
    *c++ = sizeof(OID_ECDSA_WITH_SHA256) + 2;
    c = der_encode_oid(c, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256));
    
    // SignatureValue (BIT STRING with DER-encoded ECDSA signature)
    uint8_t sig_der[72];
    uint8_t* s = sig_der;
    *s++ = ASN1_SEQUENCE;
    uint8_t* sig_len_pos = s++;
    s = der_encode_integer(s, signature, 32); // R
    s = der_encode_integer(s, signature + 32, 32); // S
    *sig_len_pos = s - sig_len_pos - 1;
    size_t sig_der_len = s - sig_der;
    
    *c++ = ASN1_BIT_STRING;
    *c++ = sig_der_len + 1;
    *c++ = 0x00; // No padding
    memcpy(c, sig_der, sig_der_len);
    c += sig_der_len;
    
    // Update certificate length
    size_t cert_len = c - cert_start - 4;  // -4 for tag + 3-byte length
    cert_len_pos[0] = 0x82;
    cert_len_pos[1] = (cert_len >> 8) & 0xFF;
    cert_len_pos[2] = cert_len & 0xFF;
    
    size_t cert_total_len = c - cert_start;
    
    // Store in output structure
    cert_out->der_data = cert;
    cert_out->der_length = cert_total_len;
    cert_out->is_valid = true;
    
    printf("[cert] Certificate generated successfully (%zu bytes)\n", cert_total_len);
    
    return ATCA_SUCCESS;
}

// Free certificate resources
void cert_free(certificate_t* cert)
{
    if (cert && cert->der_data) {
        free(cert->der_data);
        cert->der_data = NULL;
        cert->der_length = 0;
        cert->is_valid = false;
    }
}

// Print certificate in hex format
void cert_print_hex(const certificate_t* cert)
{
    if (!cert || !cert->is_valid || !cert->der_data) {
        printf("Invalid certificate\n");
        return;
    }
    
    printf("Certificate DER (hex):\n");
    for (size_t i = 0; i < cert->der_length; i++) {
        printf("%02X", cert->der_data[i]);
        if ((i + 1) % 32 == 0 && i < cert->der_length - 1) {
            printf("\n");
        }
    }
    printf("\n");
}

// Print certificate in PEM format
void cert_print_pem(const certificate_t* cert)
{
    if (!cert || !cert->is_valid || !cert->der_data) {
        printf("Invalid certificate\n");
        return;
    }
    
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    printf("-----BEGIN CERTIFICATE-----\n");
    
    size_t i = 0;
    int line_len = 0;
    
    while (i < cert->der_length) {
        uint32_t val = 0;
        int bits = 0;
        
        // Collect 3 bytes
        for (int j = 0; j < 3 && i < cert->der_length; j++) {
            val = (val << 8) | cert->der_data[i++];
            bits += 8;
        }
        
        // Pad to 24 bits
        val <<= (24 - bits);
        
        // Output 4 base64 chars
        for (int j = 0; j < 4; j++) {
            if (bits > 0) {
                printf("%c", base64_chars[(val >> 18) & 0x3F]);
                val <<= 6;
                bits -= 6;
                line_len++;
            } else {
                printf("=");
                line_len++;
            }
            
            if (line_len >= 64) {
                printf("\n");
                line_len = 0;
            }
        }
    }
    
    if (line_len > 0) printf("\n");
    printf("-----END CERTIFICATE-----\n");
}

// Convert certificate to base64 string
bool cert_to_base64(const certificate_t* cert, char* output, size_t output_size)
{
    if (!cert || !cert->is_valid || !cert->der_data || !output || output_size == 0) {
        return false;
    }
    
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    size_t i = 0;
    size_t out_idx = 0;
    
    // Encode certificate data to base64
    while (i < cert->der_length && out_idx < output_size - 5) {
        uint32_t val = 0;
        int bits = 0;
        
        // Collect 3 bytes
        for (int j = 0; j < 3 && i < cert->der_length; j++) {
            val = (val << 8) | cert->der_data[i++];
            bits += 8;
        }
        
        // Pad to 24 bits
        val <<= (24 - bits);
        
        // Output 4 base64 chars
        for (int j = 0; j < 4; j++) {
            if (out_idx >= output_size - 1) {
                output[output_size - 1] = '\0';
                return false; // Buffer too small
            }
            
            if (bits > 0) {
                output[out_idx++] = base64_chars[(val >> 18) & 0x3F];
                val <<= 6;
                bits -= 6;
            } else {
                output[out_idx++] = '=';
            }
        }
    }
    
    output[out_idx] = '\0';
    return true;
}
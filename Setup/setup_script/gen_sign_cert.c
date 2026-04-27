/**
 * Creates a self-signed X.509 certificate:
 * 1. Uses/generates ECC key in Slot 0
 * 2. Builds X.509 TBSCertificate structure
 * 3. Signs with Slot 0
 * 4. Outputs DER and PEM formats
 */

#include <stdio.h>
#include <string.h>
#include <time.h>
#include "pico/stdlib.h"
#include "hardware/i2c.h"
#include "cryptoauthlib.h"

#define I2C_CONTROLLER      i2c0
#define I2C_SDA_PIN         4
#define I2C_SCL_PIN         5
#define I2C_FREQUENCY       100000

static ATCAIfaceCfg atecc_cfg = {
    .iface_type = ATCA_I2C_IFACE,
    .devtype    = ATECC608B,
    .atcai2c    = {
        .address    = 0xC0 >> 1,
        .bus        = 0,
        .baud       = I2C_FREQUENCY
    },
    .wake_delay = 1500,
    .rx_retries = 1,
    .cfg_data   = NULL
};

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
static const uint8_t OID_EC_PUBLIC_KEY[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01}; // 1.2.840.10045.2.1
static const uint8_t OID_SECP256R1[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}; // 1.2.840.10045.3.1.7
static const uint8_t OID_ECDSA_WITH_SHA256[] = {0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02}; // 1.2.840.10045.4.3.2
static const uint8_t OID_COMMON_NAME[] = {0x55, 0x04, 0x03}; // 2.5.4.3
static const uint8_t OID_ORGANIZATION[] = {0x55, 0x04, 0x0A}; // 2.5.4.10
static const uint8_t OID_COUNTRY[] = {0x55, 0x04, 0x06}; // 2.5.4.6

// Simple DER encoder
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

static uint8_t* der_encode_tag_length(uint8_t* p, uint8_t tag, size_t len) {
    *p++ = tag;
    return der_encode_length(p, len);
}

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

static uint8_t* der_encode_oid(uint8_t* p, const uint8_t* oid, size_t len) {
    p = der_encode_tag_length(p, ASN1_OID, len);
    memcpy(p, oid, len);
    return p + len;
}

static uint8_t* der_encode_string(uint8_t* p, uint8_t tag, const char* str) {
    size_t len = strlen(str);
    p = der_encode_tag_length(p, tag, len);
    memcpy(p, str, len);
    return p + len;
}

static uint8_t* der_encode_utc_time(uint8_t* p, const char* time_str) {
    // Format: YYMMDDhhmmssZ (13 chars)
    p = der_encode_tag_length(p, ASN1_UTC_TIME, 13);
    memcpy(p, time_str, 13);
    return p + 13;
}

static uint8_t* der_encode_sequence_header(uint8_t* p, size_t content_len) {
    return der_encode_tag_length(p, ASN1_SEQUENCE, content_len);
}

// Build X.509 Name (DN)
static size_t build_name(uint8_t* buf, const char* cn, const char* org, const char* country) {
    uint8_t* p = buf;
    uint8_t* seq_start = p;
    
    p++; // Tag
    uint8_t* len_pos = p;
    p++; // Length placeholder
    
    // CN
    if (cn) {
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
    if (org) {
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
    if (country) {
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
    *p++ = 65; // 64 bytes + 1 padding indicator
    *p++ = 0x00; // No padding
    *p++ = 0x04; // Uncompressed point
    memcpy(p, public_key, 64);
    p += 64;
    
    *seq_start = ASN1_SEQUENCE;
    *seq_len = p - seq_len - 1;
    
    return p - buf;
}

// SHA-256 implementation using ATECC608
static void sha256_atca(const uint8_t* data, size_t len, uint8_t* hash) {
    // Use single-call SHA-256 (simpler)
    ATCA_STATUS status = atcab_sha(len, data, hash);
    
    if (status != ATCA_SUCCESS) {
        printf("⚠️ SHA failed, using block method\n");
        
        // Fallback: use start/update/end
        atcab_sha_start();
        
        // Process in 64-byte blocks
        size_t remaining = len;
        const uint8_t* p = data;
        
        while (remaining >= 64) {
            atcab_sha_update(p);
            p += 64;
            remaining -= 64;
        }
        
        // Finish with remaining bytes
        atcab_sha_end(hash, remaining, p);
    }
}

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s:\n", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
        if ((i + 1) % 32 == 0 && i < len - 1) printf("\n");
    }
    printf("\n");
}

static void print_pem(const char* type, const uint8_t* der, size_t der_len) {
    static const char base64_chars[] = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    printf("-----BEGIN %s-----\n", type);
    
    size_t i = 0;
    int line_len = 0;
    
    while (i < der_len) {
        uint32_t val = 0;
        int bits = 0;
        
        // Collect 3 bytes
        for (int j = 0; j < 3 && i < der_len; j++) {
            val = (val << 8) | der[i++];
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
    printf("-----END %s-----\n", type);
}

int main(void) {
    stdio_init_all();
    sleep_ms(2000);
    
    printf("\n╔══════════════════════════════════════╗\n");
    printf("║  X.509 Self-Signed Certificate      ║\n");
    printf("║  Generator - Slot 0                  ║\n");
    printf("╚══════════════════════════════════════╝\n");
    
    // Initialize
    i2c_init(I2C_CONTROLLER, I2C_FREQUENCY);
    gpio_set_function(I2C_SDA_PIN, GPIO_FUNC_I2C);
    gpio_set_function(I2C_SCL_PIN, GPIO_FUNC_I2C);
    gpio_pull_up(I2C_SDA_PIN);
    gpio_pull_up(I2C_SCL_PIN);
    printf("\n✅ I2C initialized\n");
    
    ATCA_STATUS status = atcab_init(&atecc_cfg);
    if (status != ATCA_SUCCESS) {
        printf("❌ Init failed\n");
        return 1;
    }
    printf("✅ CryptoAuthLib initialized\n");
    
    // Get or generate key in Slot 0
    printf("\n--- Step 1: Get Key from Slot 0 ---\n");
    uint8_t public_key[64];
    
    status = atcab_get_pubkey(0, public_key);
    if (status != ATCA_SUCCESS) {
        printf("No key in Slot 0, generating...\n");
        status = atcab_genkey(0, NULL);
        if (status != ATCA_SUCCESS) {
            printf("❌ GenKey failed\n");
            atcab_release();
            return 1;
        }
        status = atcab_get_pubkey(0, public_key);
        if (status != ATCA_SUCCESS) {
            printf("❌ Get pubkey failed\n");
            atcab_release();
            return 1;
        }
    }
    
    printf("✅ Public key from Slot 0:\n");
    print_hex("  ", public_key, 64);
    
    // Build TBSCertificate
    printf("\n--- Step 2: Build TBSCertificate ---\n");
    
    uint8_t tbs_cert[512];
    uint8_t* p = tbs_cert;
    uint8_t* tbs_start = p;
    
    p++; // Sequence tag
    uint8_t* tbs_len_pos = p;
    p += 2; // Length placeholder (2 bytes)
    
    // Version [0] EXPLICIT v3
    *p++ = ASN1_CONTEXT_SPECIFIC | 0;
    *p++ = 3;
    *p++ = ASN1_INTEGER;
    *p++ = 1;
    *p++ = 2; // v3
    
    // Serial Number (random)
    uint8_t serial[20] = {0};
    atcab_random(serial);
    p = der_encode_integer(p, serial, 20);
    
    // Signature Algorithm
    *p++ = ASN1_SEQUENCE;
    *p++ = sizeof(OID_ECDSA_WITH_SHA256) + 2;
    p = der_encode_oid(p, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256));
    
    // Issuer (same as Subject for self-signed)
    size_t issuer_len = build_name(p, "PICO_TEAMIS18", "SIT", "SG");
    p += issuer_len;
    
    // Validity
    *p++ = ASN1_SEQUENCE;
    *p++ = 30; // 2 * 13 + 4
    p = der_encode_utc_time(p, "250101000000Z"); // notBefore: Jan 1, 2025
    p = der_encode_utc_time(p, "350101000000Z"); // notAfter: Jan 1, 2035
    
    // Subject (same as Issuer)
    size_t subject_len = build_name(p, "PICO_TEAMIS18", "SIT", "SG");
    p += subject_len;
    
    // SubjectPublicKeyInfo
    size_t spki_len = build_subject_public_key_info(p, public_key);
    p += spki_len;
    
    // Update TBS length
    size_t tbs_len = p - tbs_start - 3;
    *tbs_start = ASN1_SEQUENCE;
    *(tbs_len_pos) = 0x82;
    *(tbs_len_pos + 1) = (tbs_len >> 8) & 0xFF;
    *(tbs_len_pos + 2) = tbs_len & 0xFF;
    
    size_t tbs_total_len = p - tbs_start;
    printf("✅ TBSCertificate built (%zu bytes)\n", tbs_total_len);
    
    // Hash TBSCertificate
    printf("\n--- Step 3: Hash TBSCertificate ---\n");
    uint8_t tbs_hash[32];
    sha256_atca(tbs_start, tbs_total_len, tbs_hash);
    print_hex("SHA-256 hash", tbs_hash, 32);
    
    // Sign with Slot 0
    printf("\n--- Step 4: Sign with Slot 0 ---\n");
    uint8_t signature[64];
    status = atcab_sign(0, tbs_hash, signature);
    if (status != ATCA_SUCCESS) {
        printf("❌ Sign failed: 0x%08X\n", status);
        atcab_release();
        return 1;
    }
    printf("✅ Signature created:\n");
    print_hex("  ", signature, 64);
    
    // Build final certificate
    printf("\n--- Step 5: Build Final Certificate ---\n");
    
    uint8_t cert[1024];
    uint8_t* c = cert;
    uint8_t* cert_start = c;
    
    c++; // Sequence tag
    uint8_t* cert_len_pos = c;
    c += 2; // Length placeholder
    
    // TBSCertificate
    memcpy(c, tbs_start, tbs_total_len);
    c += tbs_total_len;
    
    // SignatureAlgorithm
    *c++ = ASN1_SEQUENCE;
    *c++ = sizeof(OID_ECDSA_WITH_SHA256) + 2;
    c = der_encode_oid(c, OID_ECDSA_WITH_SHA256, sizeof(OID_ECDSA_WITH_SHA256));
    
    // SignatureValue (BIT STRING)
    // ECDSA signature must be in DER format: SEQUENCE { r INTEGER, s INTEGER }
    uint8_t sig_der[72]; // Max size
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
    size_t cert_len = c - cert_start - 3;
    *cert_start = ASN1_SEQUENCE;
    *(cert_len_pos) = 0x82;
    *(cert_len_pos + 1) = (cert_len >> 8) & 0xFF;
    *(cert_len_pos + 2) = cert_len & 0xFF;
    
    size_t cert_total_len = c - cert_start;
    printf("✅ Certificate built (%zu bytes)\n", cert_total_len);
    
    // Output DER
    printf("\n═══════════════════════════════════════\n");
    printf("  DER Format (hex)\n");
    printf("═══════════════════════════════════════\n");
    print_hex("Certificate", cert_start, cert_total_len);
    
    // Output PEM
    printf("\n═══════════════════════════════════════\n");
    printf("  PEM Format\n");
    printf("═══════════════════════════════════════\n");
    print_pem("CERTIFICATE", cert_start, cert_total_len);
    
    // Summary
    printf("\n═══════════════════════════════════════\n");
    printf("  Summary\n");
    printf("═══════════════════════════════════════\n");
    printf("\n✅ Self-signed certificate created!\n");
    printf("\nCertificate Details:\n");
    printf("  Subject: CN=PICO_TEAMIS18, O=SIT, C=SG\n");
    printf("  Issuer: CN=PICO_TEAMIS18, O=SIT, C=SG\n");
    printf("  Valid: Jan 1, 2025 - Jan 1, 2035\n");
    printf("  Algorithm: ECDSA with SHA-256\n");
    printf("  Curve: secp256r1 (P-256)\n");
    printf("  Key: Slot 0\n");
    
    printf("\n📝 Usage:\n");
    printf("  • Copy PEM output to .crt file\n");
    printf("  • Use in TLS/mTLS\n");
    printf("  • Private key stays in Slot 0\n");
    printf("  • Verify: openssl x509 -in cert.crt -text -noout\n");
    
    atcab_release();
    
    while (true) {
        tight_loop_contents();
    }
    
    return 0;
}
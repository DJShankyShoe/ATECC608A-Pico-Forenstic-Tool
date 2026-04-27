#pragma once
// Shared protocol strings & constants

#define CMD_INIT                "INIT"
#define REPLY_ACK_INIT          "ACK:INIT"
#define STATE_WAIT_INIT         "STATE: WAIT_INIT"
#define STATE_GOT_INIT          "STATE: GOT_INIT"
#define STATE_ESTABLISHED       "STATE: ESTABLISHED"

// AUTH (device presents its cert)
#define CMD_CERT_REQ            "CERT_REQ"          // host asks for the device cert
#define REPLY_CERT_RESP_PREFIX  "CERT_RESP:"        // MCU replies with base64 DER chain (demo)

// (optional legacy host->MCU path kept for testing)
#define CMD_CERT_PREFIX         "CERT:"             // host supplies a cert (demo sink)
#define REPLY_CERT_RECEIVED     "CERT:RECEIVED"

// KEY EXCHANGE - New Flow
// 1. Host sends pub key → 2. Pico processes & generates AES key → 3. Pico sends pub key
// 4. Host processes → 5. Host sends OK → 6. Encrypted test exchange → 7. Secure channel established
#define CMD_ECDH_HOST_PREFIX    "ECDH_PUB_HOST:"
#define REPLY_ECDH_MCU_PREFIX   "ECDH_PUB_MCU:"
#define CMD_HOST_READY          "HOST_READY"        // Host confirms it processed Pico's pub key
#define REPLY_TEST_ENC          "TEST_ENC:"         // Pico sends encrypted test message
#define CMD_TEST_RESPONSE       "TEST_RESPONSE:"    // Host sends encrypted response
#define REPLY_CHANNEL_OK        "CHANNEL_OK"        // Pico confirms secure channel established
#define REPLY_ERR_NO_ECDH       "ERR:NO_ECDH"

// USER AUTH (after secure channel established, host prompts human, sends password to MCU)
#define CMD_USER_AUTH_PREFIX     "USER_AUTH:"         // host → MCU: USER_AUTH:<password>
#define REPLY_USER_AUTH_OK       "USER_AUTH_OK"       // MCU  → host: password accepted
#define REPLY_USER_AUTH_FAIL     "USER_AUTH_FAIL"     // MCU  → host: password rejected
#define KILL_SESSION             "KILL_SESSION"         // MCU kills session on auth fail    
#define CMD_REQUEST_PASSWORD     "REQUEST_PASSWORD"   // Pico requests password from host

// ENCRYPTED CHANNEL (demo XOR stream)
#define CMD_ENC_PREFIX          "ENC:"

// Misc
#define CMD_BYE                 "bye"
#define REPLY_BYE               "BYE"

// ---- Telemetry (new protocol flow) ----
#define CMD_SENDING_CHUNK_PREFIX   "SENDING_CHUNK:"      // Host → MCU
#define REPLY_READY_TO_RECEIVE     "READY_TO_RECEIVE"    // MCU  → Host
#define CMD_DATA_PREFIX            "DATA:"               // Host → MCU (b64 encrypted chunk)
#define REPLY_CHUNK_RECEIVED       "CHUNK_RECEIVED"      // MCU  → Host (acknowledge)
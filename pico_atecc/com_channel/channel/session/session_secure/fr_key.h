#pragma once
#include "session.h"
#include <stdbool.h>
#include <stdint.h>

/**
 * @brief Handle key exchange commands
 * 
 * Implements ECDH-based session key establishment using ATECC608:
 * 1. Receives host's ephemeral public key
 * 2. Generates MCU's ephemeral key in Slot 2
 * 3. Performs ECDH to derive session key
 * 4. Sends MCU's ephemeral public key to host
 * 
 * @param s Session state
 * @param line Command line to process
 * @return true if line was handled, false otherwise
 */
bool fr_key_handle_line(session_t* s, const char* line);

/**
 * @brief Legacy seed derivation function (kept for compatibility)
 * 
 * @param shared_secret Shared secret string
 * @param transcript Transcript string
 * @return Derived seed value
 */
uint32_t fr_key_derive_seed(const char* shared_secret, const char* transcript);

/**
 * @brief Check if secure channel is established
 * 
 * @param s Session state
 * @return true if channel is established
 */
bool fr_key_is_channel_established(session_t* s);
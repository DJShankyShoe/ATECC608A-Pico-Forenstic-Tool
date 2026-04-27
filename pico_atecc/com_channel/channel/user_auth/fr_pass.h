#pragma once
#include "session.h"
#include <stdbool.h>

// FR-PASS: Password authentication module
// Handles user authentication after secure channel is established

// Initialize password module (called after secure channel established)
void fr_pass_init(void);

// Handle password-related commands
// Returns true if the line was handled
bool fr_pass_handle_line(session_t* s, const char* line);

// Check if user is authenticated
bool fr_pass_is_authenticated(void);

// Get the stored password (for key derivation)
const char* fr_pass_get_password(void);

// Clear password state
void fr_pass_clear(void);
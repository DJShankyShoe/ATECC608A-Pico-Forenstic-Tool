#pragma once
#include "session.h"
#include <stdbool.h>

// FR-AUTH: device presents cert on request; legacy CERT: sink kept.
// Returns true if handled.
bool fr_auth_handle_line(session_t* s, const char* line);
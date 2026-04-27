#pragma once
#include "session.h"
#include <stdbool.h>

// FR-CHAN (demo): handle ENC:<b64> by decrypting with test keystream, dump plaintext,
// reply ENC:<b64> of "REPLY:OK from MCU"
bool fr_chan_handle_line(session_t* s, const char* line);
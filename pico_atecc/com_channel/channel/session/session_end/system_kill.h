// system_kill.h
#ifndef SYSTEM_KILL_H
#define SYSTEM_KILL_H

#include <stdbool.h>
#include "session.h"

// Perform full system reset (watchdog reset)
void system_hard_reset(void);

// Kill session and cleanup (graceful shutdown)
void system_kill_session(session_t* s);

#endif // SYSTEM_KILL_H
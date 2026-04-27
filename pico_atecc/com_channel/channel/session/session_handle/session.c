#include "session.h"
#include <string.h>

void session_init(session_t* s) {
    memset(s, 0, sizeof(*s));
}

void session_zeroize(session_t* s) {
    memset(s, 0, sizeof(*s));
}

// system_kill.c
#include "system_kill.h"
#include "pico/stdlib.h"
#include "hardware/watchdog.h"
#include "hardware/sync.h"
#include "tusb.h"
#include "fr_auth.h"
#include "protocol.h"
#include <stdio.h>

void system_hard_reset(void) {
    watchdog_enable(1, 1);
    while(1) {
        tight_loop_contents();
    }
}

void system_kill_session(session_t* s) {
    printf(KILL_SESSION "\n");
    fflush(stdout);
    
    tud_disconnect();
    sleep_ms(100);
    
    if (s) {
        session_zeroize(s);
    }
    
    uint32_t status = save_and_disable_interrupts();
    sleep_ms(100);
    
    system_hard_reset();
}
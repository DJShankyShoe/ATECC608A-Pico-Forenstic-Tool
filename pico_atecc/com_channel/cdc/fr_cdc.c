#include "fr_cdc.h"
#include "tusb.h"
#include "pico/time.h"
#include <stdio.h>

bool fr_cdc_wait_for_port_open(uint32_t timeout_ms) {
    uint32_t start = to_ms_since_boot(get_absolute_time());
    for (;;) {
        bool dtr = (tud_cdc_get_line_state() & 0x01) != 0;
        if (tud_cdc_connected() && dtr)
            return true;
        if (timeout_ms && (to_ms_since_boot(get_absolute_time()) - start >= timeout_ms))
            return false;
        sleep_ms(5);
    }
}

void fr_cdc_banner(void) {
    printf(">>> FORENSIC DEVICE READY\n");
    printf("STATE: WAIT_INIT\n");
    fflush(stdout);
}

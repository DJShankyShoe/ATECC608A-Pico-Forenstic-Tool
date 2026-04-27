#pragma once
#include <stdbool.h>
#include <stdint.h>

void fr_cdc_banner(void);

// Wait until host opens the serial port (DTR=1).
// timeout_ms = 0 -> wait forever. Returns true if opened.
bool fr_cdc_wait_for_port_open(uint32_t timeout_ms);

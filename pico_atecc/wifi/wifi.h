#ifndef WIFI_H
#define WIFI_H

#include <stdbool.h>
#include <stdint.h>

// WiFi Status enum
typedef enum {
    WIFI_STATUS_DISCONNECTED,
    WIFI_STATUS_CONNECTING,
    WIFI_STATUS_CONNECTED,
    WIFI_STATUS_FAILED
} wifi_status_t;

// Public function declarations
void wifi_set_credentials(const char* ssid, const char* password, uint32_t timeout_ms);
const char* wifi_get_status_string(void);
int wifi_connect(const char* ssid, const char* password, uint32_t timeout_ms);
bool wifi_is_connected(void);
void wifi_thread_core1(void);
wifi_status_t wifi_get_status(void);
void wifi_thread_stop(void);

#endif // WIFI_H

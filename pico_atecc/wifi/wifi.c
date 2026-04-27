#include "wifi.h"
#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/netif.h"

// Configuration constants
#define WIFI_TIMEOUT_MS 30000
#define WIFI_RECONNECT_DELAY_MS 5000

// Module-level state
static volatile wifi_status_t wifi_status = WIFI_STATUS_DISCONNECTED;
static volatile bool wifi_thread_running = false;

// Credentials storage (ADDED - this was missing!)
static const char* stored_ssid = NULL;
static const char* stored_password = NULL;
static uint32_t stored_timeout_ms = WIFI_TIMEOUT_MS;

const char* wifi_get_status_string(void) {
    switch(wifi_status) {
        case WIFI_STATUS_DISCONNECTED: return "Disconnected";
        case WIFI_STATUS_CONNECTING: return "Connecting";
        case WIFI_STATUS_CONNECTED: return "Connected";
        case WIFI_STATUS_FAILED: return "Failed";
        default: return "Unknown";
    }
}

wifi_status_t wifi_get_status(void) {
    return wifi_status;
}

void wifi_set_credentials(const char* ssid, const char* password, uint32_t timeout_ms) {
    stored_ssid = ssid;
    stored_password = password;
    stored_timeout_ms = timeout_ms;
}

int wifi_connect(const char* ssid, const char* password, uint32_t timeout_ms) {
    printf("Connecting to Wi-Fi SSID: %s\n", ssid);
    wifi_status = WIFI_STATUS_CONNECTING;
    
    cyw43_arch_enable_sta_mode();
    
    int result = cyw43_arch_wifi_connect_timeout_ms(
        ssid, 
        password, 
        CYW43_AUTH_WPA2_AES_PSK, 
        timeout_ms
    );
    
    if (result == 0) {
        wifi_status = WIFI_STATUS_CONNECTED;
        printf("Wi-Fi Connected successfully!\n");
        printf("IP Address: %s\n", ip4addr_ntoa(netif_ip4_addr(netif_list)));
        return 0;
    } else {
        wifi_status = WIFI_STATUS_FAILED;
        printf("Wi-Fi connection failed: %d\n", result);
        return result;
    }
}

bool wifi_is_connected(void) {
    return (wifi_status == WIFI_STATUS_CONNECTED) && 
           (cyw43_tcpip_link_status(&cyw43_state, CYW43_ITF_STA) == CYW43_LINK_UP);
}

void wifi_thread_stop(void) {
    wifi_thread_running = false;
}

void wifi_thread_core1(void) {
    printf("Wi-Fi thread started on Core 1\n");
    wifi_thread_running = true;
    bool server_started = false;
    
    // External function from webserver module
    extern void start_tcp_server(void);
    
    while (wifi_thread_running) {
        if (!wifi_is_connected() && wifi_status != WIFI_STATUS_CONNECTING) {
            printf("Wi-Fi disconnected, attempting to reconnect...\n");
            if (stored_ssid && stored_password) {
                wifi_connect(stored_ssid, stored_password, stored_timeout_ms);
                if (wifi_is_connected() && !server_started) {
                    start_tcp_server();
                    server_started = true;
                }
            }
        }

        if (wifi_is_connected() && !server_started) {
            start_tcp_server();
            server_started = true;
        }
        
        // LED status indication
        if (wifi_status == WIFI_STATUS_CONNECTED) {
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
            sleep_ms(100);
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
            sleep_ms(900);
        } else if (wifi_status == WIFI_STATUS_CONNECTING) {
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 1);
            sleep_ms(250);
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
            sleep_ms(250);
        } else {
            cyw43_arch_gpio_put(CYW43_WL_GPIO_LED_PIN, 0);
            sleep_ms(WIFI_RECONNECT_DELAY_MS);
        }
        
        cyw43_arch_poll();
    }
}

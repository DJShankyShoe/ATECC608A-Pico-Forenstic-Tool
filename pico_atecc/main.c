#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "pico/multicore.h"
#include "bsp/board.h"
#include "tusb.h"
#include "lwip/netif.h"

#include "protocol.h"
#include "session.h"
#include "fr_cdc.h"
#include "fr_auth.h"
#include "fr_key.h"
#include "fr_chan.h"
#include "fr_pass.h"

#include "rubber_ducky.h"
#include "led_status.h"
#include "atecc.h"

#include "wifi.h"
#include "webserver_pico.h"
#include "sd_card.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

// Wi-Fi Configuration
#define WIFI_SSID           "ShankCert"
#define WIFI_PASSWORD       "eoRo537Ty"
#define WIFI_TIMEOUT_MS     30000

// Web Server Configuration
#define WEB_USERNAME        "admin"
#define WEB_PASSWORD        "password"
#define WEB_PORT            8080

// HID Payload Configuration
#define PAYLOAD_DIR         "C:\\Users\\Shank\\Documents\\Pico-v1.5.1\\pico-examples\\embed_project\\integrate"
#define PAYLOAD_FILE        "payload.py"

// ============================================================================
// GLOBAL STATE
// ============================================================================

// Device states
typedef enum {
    STATE_INIT,
    STATE_WAIT_USB_MOUNTED,
    STATE_HID_RUNNING,
    STATE_HID_COMPLETE,
    STATE_CDC_INIT,
    STATE_CDC_RUNNING,
    STATE_WEBSERVER_INIT,
    STATE_WEBSERVER_RUNNING,
    STATE_ERROR
} device_state_t;

static session_t g_session;
static device_state_t current_state = STATE_INIT;
static bool hid_demo_done = false;
static bool g_sd_available = false;
static bool g_wifi_initialized = false;
static bool g_webserver_running = false;
static bool g_atecc_available = false;

// ============================================================================
// FUNCTION DECLARATIONS
// ============================================================================

static bool initialize_all_systems(void);
static bool wifi_webserver_init(void);

static void handle_line(const char* line);
static void emulate_hid_demo(void);
static void update_led_for_state(device_state_t state);
static void transition_to_state(device_state_t new_state);

// USB callbacks
void tud_mount_cb(void);
void tud_umount_cb(void);
void tud_suspend_cb(bool remote_wakeup_en);
void tud_resume_cb(void);

// HID callbacks
void tud_hid_report_complete_cb(uint8_t instance, uint8_t const* report, uint16_t len);
uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t* buffer, uint16_t reqlen);
void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, hid_report_type_t report_type, uint8_t const* buffer, uint16_t bufsize);

// ============================================================================
// INITIALIZATION FUNCTIONS
// ============================================================================

/**
 * Master initialization function - initializes all subsystems
 * Returns: true if critical systems initialized successfully
 */
static bool initialize_all_systems(void) {
    printf("\n========================================\n");
    printf("  Pico W Integrated System\n");
    printf("  HID + CDC + WiFi + WebServer\n");
    printf("========================================\n\n");
    
    // Step 1: Core hardware
    printf("[INIT] Step 1: Initializing core hardware...\n");
    board_init();
    tusb_init();
    stdio_usb_init();
    led_status_init();
    printf("[INIT] ✓ Core hardware initialized\n\n");
    
    // Step 2: Session management
    printf("[INIT] Step 2: Initializing session...\n");
    session_init(&g_session);
    printf("[INIT] ✓ Session initialized\n\n");
    
    // Step 3: ATECC608 cryptographic chip
    printf("[INIT] Step 3: Initializing ATECC608 crypto chip...\n");
    if (atecc_init()) {
        g_atecc_available = true;
        printf("[INIT] ✓ ATECC608 available\n");
    } else {
        g_atecc_available = false;
        printf("[INIT] ⚠ ATECC608 not available\n");
        return false;
    }
    printf("\n");
    
    // Step 4: SD card (optional)
    printf("[INIT] Step 4: Initializing SD card...\n");
    if (sd_init()) {
        g_sd_available = true;
        printf("[INIT] ✓ SD card available\n");
    } else {
        g_sd_available = false;
        printf("[INIT] ⚠ SD card not available\n");
        printf("[INIT]   Check: Card inserted, FAT32 format, wiring\n");
        return false;
    }
    printf("\n");
    
    printf("[INIT] All systems initialized successfully!\n");
    printf("========================================\n\n");
    
    return true;
}

/**
 * Initialize WiFi and web server
 */
static bool wifi_webserver_init(void) {
    printf("\n[WiFi] Initializing WiFi subsystem...\n");
    
    // Initialize CYW43 (Wi-Fi chip)
    if (cyw43_arch_init()) {
        printf("[WiFi] ✗ Failed to initialize CYW43 chip\n");
        return false;
    }
    printf("[WiFi] ✓ WiFi chip initialized\n");
    
    // Set Wi-Fi credentials
    wifi_set_credentials(WIFI_SSID, WIFI_PASSWORD, WIFI_TIMEOUT_MS);
    
    // Launch Wi-Fi management thread on Core 1
    printf("[WiFi] Starting WiFi connection on Core 1...\n");
    multicore_launch_core1(wifi_thread_core1);
    
    // Wait for Wi-Fi connection
    printf("[WiFi] Connecting to '%s'...\n", WIFI_SSID);
    int timeout_count = 0;
    while (!wifi_is_connected() && timeout_count < 60) {  // 30 second timeout
        printf(".");
        if (timeout_count % 10 == 9) printf("\n");
        sleep_ms(500);
        timeout_count++;
    }
    printf("\n");
    
    if (!wifi_is_connected()) {
        printf("[WiFi] ✗ Connection timeout\n");
        return false;
    }
    
    printf("[WiFi] ✓ Connected to '%s'\n", WIFI_SSID);
    
    // Configure web server
    printf("[Web] Configuring web server...\n");
    webserver_set_auth(WEB_USERNAME, WEB_PASSWORD);
    
    // Start the TCP server
    start_tcp_server();
    printf("[Web] ✓ Web server started on port %d\n", WEB_PORT);
    
    // Display server information
    printf("\n========================================\n");
    printf("      WEB SERVER READY!\n");
    printf("========================================\n");
    printf("IP Address:  %s\n", ip4addr_ntoa(netif_ip4_addr(netif_list)));
    printf("Port:        %d\n", WEB_PORT);
    printf("URL:         http://%s:%d\n", ip4addr_ntoa(netif_ip4_addr(netif_list)), WEB_PORT);
    printf("\n*** LOGIN CREDENTIALS ***\n");
    printf("Username:    %s\n", WEB_USERNAME);
    printf("Password:    %s\n", WEB_PASSWORD);
    printf("========================================\n");
    printf("SD Card:     %s\n", g_sd_available ? "Available" : "Not Available");
    
    if (g_sd_available) {
        int file_count = sd_list_files();
        printf("Files:       %d\n", file_count);
    }
    
    printf("========================================\n\n");
    
    g_wifi_initialized = true;
    return true;
}

/**
 * Check if SD card is available
 */
bool is_sd_available(void) {
    return g_sd_available && sd_is_mounted();
}

// ============================================================================
// CDC COMMAND HANDLING
// ============================================================================

/**
 * Handle CDC command lines
 */
static void handle_line(const char* line) {
    if (!line || !*line) return;

    if (strcmp(line, CMD_INIT) == 0) {
        g_session.got_init = true;
        printf(REPLY_ACK_INIT "\n");
        printf(STATE_GOT_INIT "\n");
        fflush(stdout);
        return;
    }

    if (strcmp(line, CMD_BYE) == 0) {
        printf(REPLY_BYE "\n");
        fflush(stdout);
        session_zeroize(&g_session);
        session_init(&g_session);
        printf(STATE_WAIT_INIT "\n");
        fflush(stdout);
        return;
    }

    if (fr_auth_handle_line(&g_session, line)) return;
    if (fr_key_handle_line(&g_session, line))  return;
    if (fr_pass_handle_line(&g_session, line)) return;
    if (fr_chan_handle_line(&g_session, line)) return;

    printf("DUMP:unexpected:%s\n", line);
    fflush(stdout);
}

// ============================================================================
// HID PAYLOAD
// ============================================================================

/**
 * HID payload – opens CMD (normal user), cd's, runs payload.py
 */
void emulate_hid_demo(void) {
    static char ducky_payload[4096];

    printf("[HID] Reading rubber_exec.txt from SD card...\n");

    // SD must be present AND mounted
    if (!g_sd_available || !sd_is_mounted()) {
        printf("[HID] ERROR: SD card not available. HID will NOT run.\n");
        hid_demo_done = true;
        transition_to_state(STATE_HID_COMPLETE);
        return;
    }

    // File must exist
    if (!sd_file_exists("rubber_exec.txt")) {
        printf("[HID] ERROR: rubber_exec.txt not found. HID will NOT run.\n");
        hid_demo_done = true;
        transition_to_state(STATE_HID_COMPLETE);
        return;
    }

    // Get file size
    size_t file_size;
    if (sd_get_file_size("rubber_exec.txt", &file_size) != SD_OK) {
        printf("[HID] ERROR: Failed to get file size. HID will NOT run.\n");
        hid_demo_done = true;
        transition_to_state(STATE_HID_COMPLETE);
        return;
    }

    if (file_size >= sizeof(ducky_payload)) {
        printf("[HID] ERROR: File too large (%zu bytes). HID will NOT run.\n",
               file_size);
        hid_demo_done = true;
        transition_to_state(STATE_HID_COMPLETE);
        return;
    }

    // Read file
    size_t bytes_read;
    int result = sd_read_file(
        "rubber_exec.txt",
        (uint8_t*)ducky_payload,
        sizeof(ducky_payload) - 1,
        &bytes_read
    );

    if (result != SD_OK) {
        printf("[HID] ERROR: Failed to read file. HID will NOT run.\n");
        hid_demo_done = true;
        transition_to_state(STATE_HID_COMPLETE);
        return;
    }

    ducky_payload[bytes_read] = '\0';
    printf("[HID] Loaded %zu bytes from rubber_exec.txt\n", bytes_read);

    printf("[HID] Executing rubber ducky script...\n");
    execute_ducky_script(ducky_payload);
    sleep_ms(1000);

    hid_demo_done = true;
    transition_to_state(STATE_HID_COMPLETE);
}

// ============================================================================
// STATE MANAGEMENT
// ============================================================================

/**
 * Update LED based on current state
 */
static void update_led_for_state(device_state_t state) {
    switch (state) {
        case STATE_INIT:            
            led_status_set_state(LED_STATE_NOT_MOUNTED); 
            break;
        case STATE_WAIT_USB_MOUNTED: 
            led_status_set_state(LED_STATE_MOUNTED); 
            break;
        case STATE_HID_RUNNING:     
            led_status_set_state(LED_STATE_PAYLOAD_RUNNING); 
            break;
        case STATE_HID_COMPLETE:    
            led_status_set_state(LED_STATE_PAYLOAD_COMPLETE); 
            break;
        case STATE_CDC_INIT:
        case STATE_CDC_RUNNING:     
            led_status_set_state(LED_STATE_MOUNTED); 
            break;
        case STATE_WEBSERVER_INIT:
        case STATE_WEBSERVER_RUNNING:
            led_status_set_state(LED_STATE_MOUNTED); 
            break;
        case STATE_ERROR:           
            led_status_set_state(LED_STATE_ERROR); 
            break;
    }
}

/**
 * Handle state transitions
 */
static void transition_to_state(device_state_t new_state) {
    // Cleanup for leaving state
    switch (current_state) {
        case STATE_CDC_RUNNING:
            session_zeroize(&g_session);
            break;
        default:
            break;
    }

    current_state = new_state;
    update_led_for_state(new_state);

    // Setup for entering state
    switch (new_state) {
        case STATE_CDC_INIT:
            session_init(&g_session);
            break;
        case STATE_ERROR:
            printf("STATE: ERROR\n");
            fflush(stdout);
            break;
        default:
            break;
    }
}

// ============================================================================
// MAIN PROGRAM
// ============================================================================

int main(void) {
    // Initialize all systems
    if (!initialize_all_systems()) {
        printf("FATAL: System initialization failed\n");
        return -1;
    }
    
    transition_to_state(STATE_INIT);

    // Main state machine loop
    while (1) {
        tud_task();
        led_status_task();

        switch (current_state) {
            case STATE_INIT:
                if (tud_mounted()) {
                    transition_to_state(STATE_WAIT_USB_MOUNTED);
                }
                break;

            case STATE_WAIT_USB_MOUNTED:
                sleep_ms(200);
                transition_to_state(STATE_HID_RUNNING);
                break;

            case STATE_HID_RUNNING:
                if (!hid_demo_done) {
                    rubber_ducky_task(emulate_hid_demo);
                }
                break;

            case STATE_HID_COMPLETE:
                transition_to_state(STATE_CDC_INIT);
                break;

            case STATE_CDC_INIT: {
                session_init(&g_session);
                
                // Verify ATECC608 is available and ready
                printf("STATE: Verifying ATECC608...\n");
                fflush(stdout);
                
                if (!g_atecc_available) {
                    printf("STATE: ATECC608_NOT_AVAILABLE\n");
                    fflush(stdout);
                    transition_to_state(STATE_WEBSERVER_INIT);
                    break;
                }
                
                printf("STATE: ATECC608_READY\n");
                fflush(stdout);
                
                // Wait for CDC port to open
                if (fr_cdc_wait_for_port_open(30000)) {
                    printf("STATE: CDC_PORT_OPEN\n");
                    fflush(stdout);
                    
                    fr_cdc_banner();
                    
                    transition_to_state(STATE_CDC_RUNNING);
                } else {
                    printf("STATE: CDC_TIMEOUT\n");
                    fflush(stdout);
                    transition_to_state(STATE_WEBSERVER_INIT);
                }
                break;
            }

            case STATE_CDC_RUNNING: {
                // Start web server in parallel if not already running
                if (!g_webserver_running && !g_wifi_initialized) {
                    printf("\n[Main] Starting web server in background...\n");
                    if (wifi_webserver_init()) {
                        g_webserver_running = true;
                    }
                }
                
                // Handle CDC commands
                char buf[512];
                size_t pos = 0;

                while (current_state == STATE_CDC_RUNNING) {
                    tud_task();       
                    led_status_task();

                    int ch = getchar_timeout_us(0);
                    if (ch == PICO_ERROR_TIMEOUT) {
                        sleep_us(500);
                        continue;
                    }
                    if (ch == '\r') continue;

                    if (ch == '\n') {
                        buf[pos] = '\0';
                        handle_line(buf);
                        pos = 0;
                    } else if (pos < sizeof(buf) - 1) {
                        buf[pos++] = (char)ch;
                    } else {
                        pos = 0;
                    }
                }
                break;
            }

            case STATE_WEBSERVER_INIT: {
                printf("\nSTATE: Initializing web server...\n");
                
                if (wifi_webserver_init()) {
                    g_webserver_running = true;
                    transition_to_state(STATE_WEBSERVER_RUNNING);
                } else {
                    printf("STATE: WEBSERVER_INIT_FAILED\n");
                    transition_to_state(STATE_ERROR);
                }
                break;
            }

            case STATE_WEBSERVER_RUNNING: {
                // Monitor web server status
                static uint32_t count = 0;
                static uint32_t last_file_check = 0;
                uint32_t current_time = to_ms_since_boot(get_absolute_time());
                
                // Status message every 10 seconds
                if (count % 20 == 0) {
                    printf("[%lu] Status: %s", count / 2, wifi_get_status_string());
                    if (wifi_is_connected()) {
                        printf(" | Server: http://%s:%d", 
                               ip4addr_ntoa(netif_ip4_addr(netif_list)), WEB_PORT);
                        
                        // Show storage info if SD available
                        if (g_sd_available && sd_is_mounted()) {
                            uint32_t total_kb, free_kb;
                            if (sd_get_storage_info(&total_kb, &free_kb) == SD_OK) {
                                printf(" | SD: %.1f MB free", free_kb / 1024.0f);
                            }
                        } else if (!g_sd_available) {
                            printf(" | SD: Not Available");
                        }
                    }
                    printf("\n");
                }
                
                // Refresh file list every 60 seconds
                if (g_sd_available && sd_is_mounted() && 
                    (current_time - last_file_check >= 60000)) {
                    printf("Refreshing file list...\n");
                    sd_list_files();
                    last_file_check = current_time;
                }
                
                count++;
                sleep_ms(500);
                break;
            }

            case STATE_ERROR:
                sleep_ms(1000);
                break;
        }
    }
    
    return 0;
}

// ============================================================================
// USB CALLBACKS
// ============================================================================

void tud_mount_cb(void) { 
    led_status_set_state(LED_STATE_MOUNTED); 
}

void tud_umount_cb(void) { 
    led_status_set_state(LED_STATE_NOT_MOUNTED); 
    transition_to_state(STATE_INIT); 
}

void tud_suspend_cb(bool remote_wakeup_en) { 
    (void)remote_wakeup_en; 
    led_status_set_state(LED_STATE_SUSPENDED); 
}

void tud_resume_cb(void) { 
    led_status_set_state(LED_STATE_MOUNTED); 
}

// ============================================================================
// HID CALLBACKS
// ============================================================================

void tud_hid_report_complete_cb(uint8_t instance, uint8_t const* report, uint16_t len) { 
    (void)instance; 
    (void)report; 
    (void)len; 
}

uint16_t tud_hid_get_report_cb(uint8_t instance, uint8_t report_id, 
                               hid_report_type_t report_type, uint8_t* buffer, 
                               uint16_t reqlen) { 
    (void)instance; 
    (void)report_id; 
    (void)report_type; 
    (void)buffer; 
    (void)reqlen;
    return 0; 
}

void tud_hid_set_report_cb(uint8_t instance, uint8_t report_id, 
                          hid_report_type_t report_type, uint8_t const* buffer, 
                          uint16_t bufsize) { 
    (void)instance; 
    (void)report_id; 
    (void)report_type; 
    (void)buffer; 
    (void)bufsize; 
}
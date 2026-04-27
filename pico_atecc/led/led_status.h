#ifndef LED_STATUS_H_
#define LED_STATUS_H_

#include <stdint.h>
#include <stdbool.h>

// LED States Enum
typedef enum {
    LED_STATE_NOT_MOUNTED = 0,    // Device not mounted
    LED_STATE_MOUNTED,            // Device mounted
    LED_STATE_SUSPENDED,          // Device suspended
    LED_STATE_PAYLOAD_RUNNING,    // Payload is running
    LED_STATE_PAYLOAD_COMPLETE,   // Payload execution complete
    LED_STATE_ERROR,              // General error state
    LED_STATE_ERROR_NO_INTERNET,  // Error - No internet
    LED_STATE_ERROR_ANTIVIRUS     // Error - Antivirus blocked
} led_state_t;

// Function Prototypes
void led_status_init(void);                              // Initialize the LED system
void led_status_set_state(led_state_t state);            // Set LED state
led_state_t led_status_get_state(void);                  // Get current LED state
void led_status_task(void);                              // Periodic task to manage LED state
void led_status_flash(uint8_t count, uint32_t duration_ms);  // Flash LEDs for a certain duration
void led_status_pulse(uint32_t duration_ms);             // Pulse LEDs for a smooth transition
const char* led_status_get_state_name(led_state_t state); // Get a string name for the LED state

#endif /* LED_STATUS_H_ */

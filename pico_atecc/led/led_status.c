#include "led_status.h"
#include "bsp/board.h"
#include "hardware/gpio.h"

//--------------------------------------------------------------------+
// LED Configuration
//--------------------------------------------------------------------+

#define ONBOARD_LED_PIN    25  // Pico onboard LED
#define STATUS_LED_PIN     16  // GPIO 16 for status indication

//--------------------------------------------------------------------+
// LED State Management
//--------------------------------------------------------------------+

static led_state_t current_state = LED_STATE_NOT_MOUNTED;
static uint32_t last_blink_time = 0;
static bool led_on = false;

//--------------------------------------------------------------------+
// Private Functions
//--------------------------------------------------------------------+

static void set_onboard_led(bool state)
{
  board_led_write(state);
}

static void set_status_led(bool state)
{
  gpio_put(STATUS_LED_PIN, state);
}

//--------------------------------------------------------------------+
// Public API Implementation
//--------------------------------------------------------------------+

void led_status_init(void)
{
  // Initialize onboard LED (already done by board_init())
  // Just initialize GPIO 16 for status LED
  gpio_init(STATUS_LED_PIN);
  gpio_set_dir(STATUS_LED_PIN, GPIO_OUT);
  gpio_put(STATUS_LED_PIN, 0);  // Start OFF
  
  current_state = LED_STATE_NOT_MOUNTED;
  last_blink_time = 0;
  led_on = false;
}

void led_status_set_state(led_state_t state)
{
  current_state = state;
  last_blink_time = board_millis();
  
  // Handle immediate state changes
  switch (state)
  {
    case LED_STATE_PAYLOAD_RUNNING:
      // Pin 16 SOLID ON while payload is running
      set_status_led(true);  // This turns ON the status LED
      led_on = true;
      break;
      
    case LED_STATE_PAYLOAD_COMPLETE:
      // Pin 16 OFF when complete
      set_status_led(false); // This should turn OFF the status LED
      led_on = false;
      break;
      
    default:
      // Other states handled in task
      break;
  }
}

led_state_t led_status_get_state(void)
{
  return current_state;
}

void led_status_task(void)
{
  uint32_t current_time = board_millis();
  uint32_t interval = 0;
  
  // Determine blink interval based on state
  switch (current_state)
  {
    case LED_STATE_NOT_MOUNTED:
      interval = 250;  // Fast blink - not mounted
      break;
      
    case LED_STATE_MOUNTED:
      interval = 1000;  // Slow blink - mounted, idle
      break;
      
    case LED_STATE_SUSPENDED:
      interval = 2500;  // Very slow blink - suspended
      break;
      
    case LED_STATE_PAYLOAD_RUNNING:
      // Pin 16 stays SOLID ON (no blinking)
      // Onboard LED can still blink to show activity
      if (current_time - last_blink_time >= 500)
      {
        last_blink_time = current_time;
        led_on = !led_on;
        set_onboard_led(led_on);
        // Keep status LED always ON
        set_status_led(true);
      }
      return;
      
    case LED_STATE_PAYLOAD_COMPLETE:
      // Both LEDs OFF (no blinking)
      set_onboard_led(false);
      set_status_led(false);
      return;
      
    case LED_STATE_ERROR:
      interval = 100;  // Ultra fast blink - ERROR!
      break;
      
    case LED_STATE_ERROR_NO_INTERNET:
      // Blink pattern: 100ms ON, 100ms OFF, 100ms ON, 500ms OFF
      // This creates a "double blink" pattern
      {
        static uint8_t blink_phase = 0;
        static uint32_t phase_intervals[] = {100, 100, 100, 500};
        
        if (current_time - last_blink_time >= phase_intervals[blink_phase])
        {
          last_blink_time = current_time;
          led_on = !led_on;
          set_onboard_led(led_on);
          set_status_led(led_on);
          
          if (!led_on) {
            blink_phase = (blink_phase + 1) % 4;
          }
        }
      }
      return;
      
    case LED_STATE_ERROR_ANTIVIRUS:
      // Blink pattern: 100ms ON, 100ms OFF, 100ms ON, 100ms OFF, 100ms ON, 500ms OFF
      // This creates a "triple blink" pattern
      {
        static uint8_t blink_phase = 0;
        static uint32_t phase_intervals[] = {100, 100, 100, 100, 100, 500};
        
        if (current_time - last_blink_time >= phase_intervals[blink_phase])
        {
          last_blink_time = current_time;
          led_on = !led_on;
          set_onboard_led(led_on);
          set_status_led(led_on);
          
          if (!led_on) {
            blink_phase = (blink_phase + 1) % 6;
          }
        }
      }
      return;
      
    default:
      interval = 1000;
      break;
  }
  
  // Standard blinking for simple states
  if (interval > 0 && (current_time - last_blink_time >= interval))
  {
    last_blink_time = current_time;
    led_on = !led_on;
    
    // Update both LEDs for standard states
    set_onboard_led(led_on);
    set_status_led(led_on);
  }
}

void led_status_flash(uint8_t count, uint32_t duration_ms)
{
  for (uint8_t i = 0; i < count; i++)
  {
    set_onboard_led(true);
    set_status_led(true);
    board_delay(duration_ms);
    
    set_onboard_led(false);
    set_status_led(false);
    board_delay(duration_ms);
  }
}

void led_status_pulse(uint32_t duration_ms)
{
  // Create a smooth pulse effect
  const uint8_t steps = 20;
  
  // Fade in
  for (uint8_t i = 0; i < steps; i++)
  {
    set_onboard_led(true);
    set_status_led(true);
    board_delay(duration_ms / (steps * 2));
    set_onboard_led(false);
    set_status_led(false);
    board_delay(duration_ms / (steps * 2));
  }
  
  // Fade out
  for (uint8_t i = steps; i > 0; i--)
  {
    set_onboard_led(true);
    set_status_led(true);
    board_delay(duration_ms / (steps * 2));
    set_onboard_led(false);
    set_status_led(false);
    board_delay(duration_ms / (steps * 2));
  }
}

const char* led_status_get_state_name(led_state_t state)
{
  switch (state)
  {
    case LED_STATE_NOT_MOUNTED: return "NOT_MOUNTED";
    case LED_STATE_MOUNTED: return "MOUNTED";
    case LED_STATE_SUSPENDED: return "SUSPENDED";
    case LED_STATE_PAYLOAD_RUNNING: return "PAYLOAD_RUNNING";
    case LED_STATE_PAYLOAD_COMPLETE: return "PAYLOAD_COMPLETE";
    case LED_STATE_ERROR: return "ERROR";
    case LED_STATE_ERROR_NO_INTERNET: return "ERROR_NO_INTERNET";
    case LED_STATE_ERROR_ANTIVIRUS: return "ERROR_ANTIVIRUS";
    default: return "UNKNOWN";
  }
}
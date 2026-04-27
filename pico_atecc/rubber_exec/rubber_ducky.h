#ifndef RUBBER_DUCKY_H_
#define RUBBER_DUCKY_H_

#include <stdint.h>
#include "../usb_desc/usb_descriptors.h"

/**
 * @brief Payload error types for LED feedback
 */
typedef enum {
  PAYLOAD_ERROR_NONE = 0,       // No error
  PAYLOAD_ERROR_NO_INTERNET,    // Network connection failed
  PAYLOAD_ERROR_ANTIVIRUS,      // Antivirus blocked execution
  PAYLOAD_ERROR_GENERAL         // General/unknown error
} payload_error_type_t;

/**
 * @brief Execute a complete Rubber Ducky script
 * 
 * Parses and executes a multi-line Rubber Ducky script with full command support.
 * 
 * Supported commands:
 * - REM <comment> or // <comment> - Comments
 * - DELAY <ms> - Wait for specified milliseconds
 * - STRING <text> - Type a string (supports all characters and symbols)
 * - ENTER - Press Enter key
 * - GUI <key> - Windows/Command key + letter
 * - CTRL <key> or CONTROL <key> - Control + key
 * - ALT <key> - Alt + key
 * - SHIFT <key> - Shift + key
 * - CTRL-ALT <key> - Ctrl+Alt combo
 * - CTRL-SHIFT <key> - Ctrl+Shift combo
 * - Special keys: ESC, TAB, BACKSPACE, DELETE, HOME, END, PAGEUP, PAGEDOWN
 *                 UP, DOWN, LEFT, RIGHT, F1-F12, PRINTSCREEN, etc.
 * 
 * @param script Null-terminated string containing the Rubber Ducky script
 */
void execute_ducky_script(const char* script);

/**
 * @brief Send a string as keyboard input
 * 
 * Types the given string character by character with full support for:
 * - Letters (a-z, A-Z)
 * - Numbers (0-9)
 * - Symbols and punctuation (!@#$%^&*(){}[]|;:'",.<>?/~`-_=+\)
 * - Spaces
 * 
 * @param str Null-terminated string to type
 */
void ducky_send_string(const char* str);

/**
 * @brief Send a key press with optional modifier
 * 
 * @param keycode HID keycode (use HID_KEY_* constants from TinyUSB)
 * @param modifier Modifier byte (use KEYBOARD_MODIFIER_* constants)
 */
void ducky_send_key_with_modifier(uint8_t keycode, uint8_t modifier);

/**
 * @brief Modular task handler for Rubber Ducky payload execution
 * 
 * Manages timing and execution of the payload. Call repeatedly in main loop.
 * 
 * @param payload_function Function pointer to payload function
 */
void rubber_ducky_task(void (*payload_function)(void));

/**
 * @brief Reset the payload execution state
 * 
 * Allows the payload to be executed again.
 */
void rubber_ducky_reset(void);

/**
 * ✅ UC1: Start monitoring for payload execution feedback
 * 
 * Begins timeout monitoring to detect if the payload successfully executes.
 * LED will indicate error if timeout expires without communication.
 * 
 * @param timeout_ms Timeout in milliseconds (typically 30000 for 30 seconds)
 */
void start_payload_monitoring(uint32_t timeout_ms);

/**
 * ✅ UC1: Signal that payload has established communication
 * 
 * Call when payload successfully communicates back to the MCU.
 * Clears timeout monitoring and sets LED to completion state.
 */
void payload_communication_detected(void);

/**
 * ✅ UC1: Set specific error type for LED pattern
 * 
 * Sets the error type before timeout expires to display specific LED pattern.
 * 
 * @param type Error type (NO_INTERNET, ANTIVIRUS, or GENERAL)
 * 
 * @example
 * // If download fails, set error type before timeout
 * payload_set_error_type(PAYLOAD_ERROR_NO_INTERNET);
 */
void payload_set_error_type(payload_error_type_t type);

/**
 * ✅ UC1: Task to monitor payload execution timeout
 * 
 * Should be called regularly in the main loop. Checks if monitoring
 * timeout has expired and triggers appropriate LED error pattern.
 */
void payload_monitoring_task(void);

#endif /* RUBBER_DUCKY_H_ */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "bsp/board.h"
#include "tusb.h"
#include "rubber_ducky.h"
#include "led_status.h"

//--------------------------------------------------------------------+
// TYPING SPEED CONFIGURATION
//--------------------------------------------------------------------+

// ⚡ SPEED PRESETS (uncomment ONE):

// Ultra Fast (10ms/10ms = 50 keystrokes/sec) - for modern systems
#define KEY_PRESS_DELAY_MS    10
#define KEY_RELEASE_DELAY_MS  10

// Fast (15ms/15ms = 33 keystrokes/sec) - recommended default
//#define KEY_PRESS_DELAY_MS    15
//#define KEY_RELEASE_DELAY_MS  15

// Medium (25ms/25ms = 20 keystrokes/sec) - very compatible
//#define KEY_PRESS_DELAY_MS    25
//#define KEY_RELEASE_DELAY_MS  25

// Slow (50ms/50ms = 10 keystrokes/sec) - original conservative speed
//#define KEY_PRESS_DELAY_MS    50
//#define KEY_RELEASE_DELAY_MS  50

//--------------------------------------------------------------------+
// Static State Management
//--------------------------------------------------------------------+

static bool payload_executed = false;
static uint32_t mount_start_time = 0;

// ✅ UC1: Payload monitoring state
static bool monitoring_active = false;
static uint32_t monitoring_start_time = 0;
static uint32_t monitoring_timeout_ms = 0;
static bool payload_communication_received = false;
static payload_error_type_t error_type = PAYLOAD_ERROR_NONE;

//--------------------------------------------------------------------+
// Character to HID Keycode Mapping
//--------------------------------------------------------------------+

typedef struct {
  char character;
  uint8_t keycode;
  uint8_t modifier;
} char_map_t;

static const char_map_t char_to_hid[] = {
  // Lowercase letters
  {'a', HID_KEY_A, 0}, {'b', HID_KEY_B, 0}, {'c', HID_KEY_C, 0}, {'d', HID_KEY_D, 0},
  {'e', HID_KEY_E, 0}, {'f', HID_KEY_F, 0}, {'g', HID_KEY_G, 0}, {'h', HID_KEY_H, 0},
  {'i', HID_KEY_I, 0}, {'j', HID_KEY_J, 0}, {'k', HID_KEY_K, 0}, {'l', HID_KEY_L, 0},
  {'m', HID_KEY_M, 0}, {'n', HID_KEY_N, 0}, {'o', HID_KEY_O, 0}, {'p', HID_KEY_P, 0},
  {'q', HID_KEY_Q, 0}, {'r', HID_KEY_R, 0}, {'s', HID_KEY_S, 0}, {'t', HID_KEY_T, 0},
  {'u', HID_KEY_U, 0}, {'v', HID_KEY_V, 0}, {'w', HID_KEY_W, 0}, {'x', HID_KEY_X, 0},
  {'y', HID_KEY_Y, 0}, {'z', HID_KEY_Z, 0},
  
  // Uppercase letters
  {'A', HID_KEY_A, KEYBOARD_MODIFIER_LEFTSHIFT}, {'B', HID_KEY_B, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'C', HID_KEY_C, KEYBOARD_MODIFIER_LEFTSHIFT}, {'D', HID_KEY_D, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'E', HID_KEY_E, KEYBOARD_MODIFIER_LEFTSHIFT}, {'F', HID_KEY_F, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'G', HID_KEY_G, KEYBOARD_MODIFIER_LEFTSHIFT}, {'H', HID_KEY_H, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'I', HID_KEY_I, KEYBOARD_MODIFIER_LEFTSHIFT}, {'J', HID_KEY_J, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'K', HID_KEY_K, KEYBOARD_MODIFIER_LEFTSHIFT}, {'L', HID_KEY_L, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'M', HID_KEY_M, KEYBOARD_MODIFIER_LEFTSHIFT}, {'N', HID_KEY_N, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'O', HID_KEY_O, KEYBOARD_MODIFIER_LEFTSHIFT}, {'P', HID_KEY_P, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'Q', HID_KEY_Q, KEYBOARD_MODIFIER_LEFTSHIFT}, {'R', HID_KEY_R, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'S', HID_KEY_S, KEYBOARD_MODIFIER_LEFTSHIFT}, {'T', HID_KEY_T, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'U', HID_KEY_U, KEYBOARD_MODIFIER_LEFTSHIFT}, {'V', HID_KEY_V, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'W', HID_KEY_W, KEYBOARD_MODIFIER_LEFTSHIFT}, {'X', HID_KEY_X, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'Y', HID_KEY_Y, KEYBOARD_MODIFIER_LEFTSHIFT}, {'Z', HID_KEY_Z, KEYBOARD_MODIFIER_LEFTSHIFT},
  
  // Numbers
  {'0', HID_KEY_0, 0}, {'1', HID_KEY_1, 0}, {'2', HID_KEY_2, 0}, {'3', HID_KEY_3, 0},
  {'4', HID_KEY_4, 0}, {'5', HID_KEY_5, 0}, {'6', HID_KEY_6, 0}, {'7', HID_KEY_7, 0},
  {'8', HID_KEY_8, 0}, {'9', HID_KEY_9, 0},
  
  // Symbols (unshifted)
  {' ', HID_KEY_SPACE, 0}, {'-', HID_KEY_MINUS, 0}, {'=', HID_KEY_EQUAL, 0},
  {'[', HID_KEY_BRACKET_LEFT, 0}, {']', HID_KEY_BRACKET_RIGHT, 0},
  {'\\', HID_KEY_BACKSLASH, 0}, {';', HID_KEY_SEMICOLON, 0}, {'\'', HID_KEY_APOSTROPHE, 0},
  {'`', HID_KEY_GRAVE, 0}, {',', HID_KEY_COMMA, 0}, {'.', HID_KEY_PERIOD, 0},
  {'/', HID_KEY_SLASH, 0},
  
  // Symbols (shifted)
  {'!', HID_KEY_1, KEYBOARD_MODIFIER_LEFTSHIFT}, {'@', HID_KEY_2, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'#', HID_KEY_3, KEYBOARD_MODIFIER_LEFTSHIFT}, {'$', HID_KEY_4, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'%', HID_KEY_5, KEYBOARD_MODIFIER_LEFTSHIFT}, {'^', HID_KEY_6, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'&', HID_KEY_7, KEYBOARD_MODIFIER_LEFTSHIFT}, {'*', HID_KEY_8, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'(', HID_KEY_9, KEYBOARD_MODIFIER_LEFTSHIFT}, {')', HID_KEY_0, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'_', HID_KEY_MINUS, KEYBOARD_MODIFIER_LEFTSHIFT}, {'+', HID_KEY_EQUAL, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'{', HID_KEY_BRACKET_LEFT, KEYBOARD_MODIFIER_LEFTSHIFT}, {'}', HID_KEY_BRACKET_RIGHT, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'|', HID_KEY_BACKSLASH, KEYBOARD_MODIFIER_LEFTSHIFT}, {':', HID_KEY_SEMICOLON, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'"', HID_KEY_APOSTROPHE, KEYBOARD_MODIFIER_LEFTSHIFT}, {'~', HID_KEY_GRAVE, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'<', HID_KEY_COMMA, KEYBOARD_MODIFIER_LEFTSHIFT}, {'>', HID_KEY_PERIOD, KEYBOARD_MODIFIER_LEFTSHIFT},
  {'?', HID_KEY_SLASH, KEYBOARD_MODIFIER_LEFTSHIFT},
};

//--------------------------------------------------------------------+
// Special Key Mapping
//--------------------------------------------------------------------+

typedef struct {
  const char* name;
  uint8_t keycode;
} special_key_t;

static const special_key_t special_keys[] = {
  {"ENTER", HID_KEY_ENTER}, {"RETURN", HID_KEY_ENTER},
  {"ESC", HID_KEY_ESCAPE}, {"ESCAPE", HID_KEY_ESCAPE},
  {"BACKSPACE", HID_KEY_BACKSPACE},
  {"TAB", HID_KEY_TAB},
  {"SPACE", HID_KEY_SPACE},
  {"CAPSLOCK", HID_KEY_CAPS_LOCK},
  {"DELETE", HID_KEY_DELETE},
  {"END", HID_KEY_END},
  {"HOME", HID_KEY_HOME},
  {"INSERT", HID_KEY_INSERT},
  {"PAGEUP", HID_KEY_PAGE_UP},
  {"PAGEDOWN", HID_KEY_PAGE_DOWN},
  {"UP", HID_KEY_ARROW_UP}, {"UPARROW", HID_KEY_ARROW_UP},
  {"DOWN", HID_KEY_ARROW_DOWN}, {"DOWNARROW", HID_KEY_ARROW_DOWN},
  {"LEFT", HID_KEY_ARROW_LEFT}, {"LEFTARROW", HID_KEY_ARROW_LEFT},
  {"RIGHT", HID_KEY_ARROW_RIGHT}, {"RIGHTARROW", HID_KEY_ARROW_RIGHT},
  {"F1", HID_KEY_F1}, {"F2", HID_KEY_F2}, {"F3", HID_KEY_F3}, {"F4", HID_KEY_F4},
  {"F5", HID_KEY_F5}, {"F6", HID_KEY_F6}, {"F7", HID_KEY_F7}, {"F8", HID_KEY_F8},
  {"F9", HID_KEY_F9}, {"F10", HID_KEY_F10}, {"F11", HID_KEY_F11}, {"F12", HID_KEY_F12},
  {"PRINTSCREEN", HID_KEY_PRINT_SCREEN},
  {"SCROLLLOCK", HID_KEY_SCROLL_LOCK},
  {"PAUSE", HID_KEY_PAUSE},
  {"BREAK", HID_KEY_PAUSE},
};

//--------------------------------------------------------------------+
// Internal Functions - ⚡ HIGH SPEED TYPING
//--------------------------------------------------------------------+

static void send_key(uint8_t keycode, uint8_t modifier)
{
  if (!tud_hid_ready()) return;

  // Press key
  uint8_t keys[6] = {keycode, 0, 0, 0, 0, 0};
  tud_hid_keyboard_report(REPORT_ID_KEYBOARD, modifier, keys);
  board_delay(KEY_PRESS_DELAY_MS);

  // Release key
  tud_hid_keyboard_report(REPORT_ID_KEYBOARD, 0, NULL);
  board_delay(KEY_RELEASE_DELAY_MS);
}

static void send_char(char c)
{
  for (size_t i = 0; i < sizeof(char_to_hid) / sizeof(char_map_t); i++)
  {
    if (char_to_hid[i].character == c)
    {
      send_key(char_to_hid[i].keycode, char_to_hid[i].modifier);
      return;
    }
  }
}

static uint8_t get_special_keycode(const char* key_name)
{
  for (size_t i = 0; i < sizeof(special_keys) / sizeof(special_key_t); i++)
  {
    if (strcmp(special_keys[i].name, key_name) == 0)
    {
      return special_keys[i].keycode;
    }
  }
  return 0;
}

static void parse_and_execute_line(char* line)
{
  // Trim whitespace
  while (*line == ' ' || *line == '\t') line++;
  if (*line == '\0' || *line == '\n' || *line == '\r') return;
  
  // Remove newline
  char* newline = strchr(line, '\n');
  if (newline) *newline = '\0';
  newline = strchr(line, '\r');
  if (newline) *newline = '\0';
  
  // REM - Comment
  if (strncmp(line, "REM ", 4) == 0 || strncmp(line, "//", 2) == 0)
  {
    return;
  }
  
  // DELAY
  if (strncmp(line, "DELAY ", 6) == 0)
  {
    int delay_ms = atoi(line + 6);
    board_delay(delay_ms);
    return;
  }
  
  // STRING
  if (strncmp(line, "STRING ", 7) == 0)
  {
    ducky_send_string(line + 7);
    return;
  }
  
  // ENTER
  if (strcmp(line, "ENTER") == 0)
  {
    send_key(HID_KEY_ENTER, 0);
    return;
  }
  
  // GUI
  if (strncmp(line, "GUI ", 4) == 0)
  {
    char key = line[4];
    if (key >= 'a' && key <= 'z')
    {
      send_key(HID_KEY_A + (key - 'a'), KEYBOARD_MODIFIER_LEFTGUI);
    }
    else if (key >= 'A' && key <= 'Z')
    {
      send_key(HID_KEY_A + (key - 'A'), KEYBOARD_MODIFIER_LEFTGUI | KEYBOARD_MODIFIER_LEFTSHIFT);
    }
    return;
  }
  
  if (strcmp(line, "GUI") == 0 || strcmp(line, "WINDOWS") == 0)
  {
    send_key(HID_KEY_GUI_LEFT, 0);
    return;
  }
  
  // CTRL-ALT
  if (strncmp(line, "CTRL-ALT ", 9) == 0 || strncmp(line, "CONTROL-ALT ", 12) == 0)
  {
    const char* key_part = (line[4] == '-') ? (line + 9) : (line + 12);
    uint8_t keycode = get_special_keycode(key_part);
    if (keycode)
    {
      send_key(keycode, KEYBOARD_MODIFIER_LEFTCTRL | KEYBOARD_MODIFIER_LEFTALT);
    }
    else
    {
      char key = key_part[0];
      if (key >= 'a' && key <= 'z')
      {
        send_key(HID_KEY_A + (key - 'a'), KEYBOARD_MODIFIER_LEFTCTRL | KEYBOARD_MODIFIER_LEFTALT);
      }
    }
    return;
  }
  
  // CTRL-SHIFT
  if (strncmp(line, "CTRL-SHIFT ", 11) == 0 || strncmp(line, "CONTROL-SHIFT ", 14) == 0)
  {
    const char* key_part = (line[4] == '-') ? (line + 11) : (line + 14);
    uint8_t keycode = get_special_keycode(key_part);
    if (keycode)
    {
      send_key(keycode, KEYBOARD_MODIFIER_LEFTCTRL | KEYBOARD_MODIFIER_LEFTSHIFT);
    }
    return;
  }
  
  // CTRL
  if (strncmp(line, "CTRL ", 5) == 0 || strncmp(line, "CONTROL ", 8) == 0)
  {
    const char* key_part = (line[4] == ' ') ? (line + 5) : (line + 8);
    char key = key_part[0];
    if (key >= 'a' && key <= 'z')
    {
      send_key(HID_KEY_A + (key - 'a'), KEYBOARD_MODIFIER_LEFTCTRL);
    }
    else if (key >= 'A' && key <= 'Z')
    {
      send_key(HID_KEY_A + (key - 'A'), KEYBOARD_MODIFIER_LEFTCTRL);
    }
    else
    {
      uint8_t keycode = get_special_keycode(key_part);
      if (keycode) send_key(keycode, KEYBOARD_MODIFIER_LEFTCTRL);
    }
    return;
  }
  
  // ALT
  if (strncmp(line, "ALT ", 4) == 0)
  {
    const char* key_part = line + 4;
    char key = key_part[0];
    if (key >= 'a' && key <= 'z')
    {
      send_key(HID_KEY_A + (key - 'a'), KEYBOARD_MODIFIER_LEFTALT);
    }
    else if (key >= 'A' && key <= 'Z')
    {
      send_key(HID_KEY_A + (key - 'A'), KEYBOARD_MODIFIER_LEFTALT);
    }
    else
    {
      uint8_t keycode = get_special_keycode(key_part);
      if (keycode) send_key(keycode, KEYBOARD_MODIFIER_LEFTALT);
    }
    return;
  }
  
  // SHIFT
  if (strncmp(line, "SHIFT ", 6) == 0)
  {
    const char* key_part = line + 6;
    uint8_t keycode = get_special_keycode(key_part);
    if (keycode)
    {
      send_key(keycode, KEYBOARD_MODIFIER_LEFTSHIFT);
    }
    return;
  }
  
  // Special keys
  uint8_t keycode = get_special_keycode(line);
  if (keycode)
  {
    send_key(keycode, 0);
    return;
  }
}

//--------------------------------------------------------------------+
// UC1: Payload Monitoring Functions with LED Feedback
//--------------------------------------------------------------------+

void start_payload_monitoring(uint32_t timeout_ms)
{
  monitoring_active = true;
  monitoring_start_time = board_millis();
  monitoring_timeout_ms = timeout_ms;
  payload_communication_received = false;
  error_type = PAYLOAD_ERROR_NONE;
}

void payload_communication_detected(void)
{
  payload_communication_received = true;
  monitoring_active = false;
  error_type = PAYLOAD_ERROR_NONE;
  
  // ✅ LED: Success - payload communicated back
  led_status_set_state(LED_STATE_PAYLOAD_COMPLETE);
}

void payload_set_error_type(payload_error_type_t type)
{
  error_type = type;
}

void payload_monitoring_task(void)
{
  if (!monitoring_active) return;
  
  // Check if timeout exceeded
  if ((board_millis() - monitoring_start_time) > monitoring_timeout_ms)
  {
    // ✅ UC1 Alternative Scenario: Timeout occurred
    monitoring_active = false;
    
    // ✅ LED: Set appropriate error pattern
    if (error_type == PAYLOAD_ERROR_NO_INTERNET)
    {
      led_status_set_state(LED_STATE_ERROR_NO_INTERNET);  // Double blink
    }
    else if (error_type == PAYLOAD_ERROR_ANTIVIRUS)
    {
      led_status_set_state(LED_STATE_ERROR_ANTIVIRUS);    // Triple blink
    }
    else
    {
      led_status_set_state(LED_STATE_ERROR);              // Fast blink
    }
  }
}

//--------------------------------------------------------------------+
// Public API Functions
//--------------------------------------------------------------------+

void ducky_send_string(const char* str)
{
  for (size_t i = 0; i < strlen(str); i++)
  {
    send_char(str[i]);
  }
}

void ducky_send_key_with_modifier(uint8_t keycode, uint8_t modifier)
{
  send_key(keycode, modifier);
}

void execute_ducky_script(const char* script)
{
  char* script_copy = malloc(strlen(script) + 1);
  if (!script_copy) return;
  
  strcpy(script_copy, script);
  
  char* line = strtok(script_copy, "\n");
  while (line != NULL)
  {
    parse_and_execute_line(line);
    line = strtok(NULL, "\n");
  }
  
  free(script_copy);
}

void rubber_ducky_task(void (*payload_function)(void))
{
  if (!tud_mounted()) 
  {
    payload_executed = false;
    mount_start_time = 0;
    return;
  }
  
  if (!payload_executed)
  {
    if (mount_start_time == 0) 
    {
      mount_start_time = board_millis();
    }
    
    if (board_millis() - mount_start_time > 3000)
    {
      if (payload_function != NULL)
      {
        payload_function();
      }
      
      payload_executed = true;
    }
  }
}

void rubber_ducky_reset(void)
{
  payload_executed = false;
  mount_start_time = 0;
  monitoring_active = false;
  payload_communication_received = false;
  error_type = PAYLOAD_ERROR_NONE;
}
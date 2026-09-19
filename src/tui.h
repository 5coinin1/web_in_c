#ifndef TUI_H
#define TUI_H

#include <stdbool.h>

// Minimal ANSI terminal UI helpers (no external dependencies).

#define TUI_RESET   "\033[0m"
#define TUI_BOLD    "\033[1m"
#define TUI_DIM     "\033[2m"
#define TUI_CYAN    "\033[36m"
#define TUI_GREEN   "\033[32m"
#define TUI_YELLOW  "\033[33m"
#define TUI_RED     "\033[31m"
#define TUI_BLUE    "\033[34m"

// Decoded key codes returned by tui_read_key().
#define TUI_KEY_NONE      0
#define TUI_KEY_ENTER     1
#define TUI_KEY_BACKSPACE 2
#define TUI_KEY_TAB       3
#define TUI_KEY_UP        4
#define TUI_KEY_DOWN      5
#define TUI_KEY_PGUP      6
#define TUI_KEY_PGDN      7
#define TUI_KEY_CTRL_C    8
#define TUI_KEY_EOF       9
#define TUI_KEY_CHAR      10   // printable character passed via *ch
#define TUI_KEY_WHEEL_UP  11
#define TUI_KEY_WHEEL_DOWN 12

// Enable ANSI escape processing (required on Windows consoles).
void tui_init(void);

// True if stdout is an interactive terminal.
bool tui_is_tty(void);

// Terminal size in character cells.
void tui_size(int *cols, int *rows);

// Put the terminal into raw input mode / restore it.
void tui_raw_enable(void);
void tui_raw_disable(void);

// Blocking key read. Returns a TUI_KEY_* value; for TUI_KEY_CHAR, *ch holds
// the character. Returns TUI_KEY_EOF if input is unavailable.
int tui_read_key(char *ch);

// Like tui_read_key but returns TUI_KEY_NONE after ms milliseconds.
int tui_read_key_timeout(char *ch, int ms);

// Clear the screen and move the cursor to the home position.
void tui_clear(void);

// Print a horizontal rule of the given width using color.
void tui_rule(int width, const char *color);

#endif

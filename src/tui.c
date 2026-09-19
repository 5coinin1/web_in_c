#include "tui.h"
#include <stdio.h>

#ifdef _WIN32
    #include <windows.h>
    #include <conio.h>
#else
    #include <unistd.h>
    #include <termios.h>
    #include <sys/ioctl.h>
    #include <fcntl.h>
#endif

static int g_raw_saved = 0;
#ifdef _WIN32
static DWORD g_saved_in_mode = 0;
#else
static struct termios g_saved_termios;
#endif

void tui_init(void) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD mode = 0;
        if (GetConsoleMode(h, &mode)) {
            SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
        }
    }
#endif
}

bool tui_is_tty(void) {
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    return (h != INVALID_HANDLE_VALUE) && GetConsoleMode(h, &mode);
#else
    return isatty(STDOUT_FILENO);
#endif
}

void tui_size(int *cols, int *rows) {
    int c = 80, r = 24;
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO info;
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE && GetConsoleScreenBufferInfo(h, &info)) {
        c = info.srWindow.Right - info.srWindow.Left + 1;
        r = info.srWindow.Bottom - info.srWindow.Top + 1;
    }
#else
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
        c = ws.ws_col;
        r = ws.ws_row;
    }
#endif
    if (cols) *cols = c;
    if (rows) *rows = r;
}

void tui_raw_enable(void) {
    if (g_raw_saved) return;
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE && GetConsoleMode(h, &g_saved_in_mode)) {
        DWORD m = g_saved_in_mode;
        m &= ~(DWORD)(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT | ENABLE_PROCESSED_INPUT);
        // Enable mouse input so the app receives wheel events. This turns off
        // console quick-edit; in Windows Terminal text can still be selected
        // by holding Shift while dragging.
        m |= ENABLE_EXTENDED_FLAGS;
        m &= ~(DWORD)ENABLE_QUICK_EDIT_MODE;
        m |= ENABLE_MOUSE_INPUT;
        SetConsoleMode(h, m);
        g_raw_saved = 1;
    }
#else
    if (tcgetattr(STDIN_FILENO, &g_saved_termios) == 0) {
        struct termios t = g_saved_termios;
        t.c_lflag &= ~(tcflag_t)(ICANON | ECHO);
        t.c_cc[VMIN] = 1;
        t.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
        g_raw_saved = 1;
    }
#endif
}

void tui_raw_disable(void) {
    if (!g_raw_saved) return;
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (h != INVALID_HANDLE_VALUE) SetConsoleMode(h, g_saved_in_mode);
#else
    tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_termios);
#endif
    g_raw_saved = 0;
}

#ifdef _WIN32
// Read the next console input event and translate it into a TUI key.
// Handles arrows, PageUp/Down and mouse wheel via INPUT_RECORD.
static int read_win_event(char *ch) {
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) return TUI_KEY_EOF;

    INPUT_RECORD rec;
    DWORD n = 0;
    for (;;) {
        if (!ReadConsoleInputW(h, &rec, 1, &n) || n == 0) return TUI_KEY_EOF;

        if (rec.EventType == KEY_EVENT) {
            KEY_EVENT_RECORD *k = &rec.Event.KeyEvent;
            if (!k->bKeyDown) continue;
            WCHAR u = k->uChar.UnicodeChar;

            if (u == L'\r' || u == L'\n') return TUI_KEY_ENTER;
            if (u == L'\b' || u == 127)   return TUI_KEY_BACKSPACE;
            if (u == L'\t')               return TUI_KEY_TAB;
            if (u == 3)                   return TUI_KEY_CTRL_C;
            if (u == 16)                  return TUI_KEY_UP;      // Ctrl+P
            if (u == 14)                  return TUI_KEY_DOWN;    // Ctrl+N
            if (u >= 32) { if (ch) *ch = (char)u; return TUI_KEY_CHAR; }

            // No unicode char (special key): use the virtual key code.
            switch (k->wVirtualKeyCode) {
                case VK_UP:    return TUI_KEY_UP;
                case VK_DOWN:  return TUI_KEY_DOWN;
                case VK_PRIOR: return TUI_KEY_PGUP;
                case VK_NEXT:  return TUI_KEY_PGDN;
                default:       return TUI_KEY_NONE;
            }
        }
        else if (rec.EventType == MOUSE_EVENT) {
            MOUSE_EVENT_RECORD *m = &rec.Event.MouseEvent;
            if (m->dwEventFlags == MOUSE_WHEELED) {
                short delta = (short)HIWORD(m->dwButtonState);
                return delta > 0 ? TUI_KEY_WHEEL_UP : TUI_KEY_WHEEL_DOWN;
            }
            continue;
        }
        else {
            continue;   // window/focus events
        }
    }
}
#else
// ---- POSIX ----
static int read_byte(void) {
    unsigned char c;
    ssize_t n = read(STDIN_FILENO, &c, 1);
    if (n <= 0) return -1;
    return c;
}

static int byte_available(int ms) {
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(STDIN_FILENO, &fds);
    struct timeval tv;
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    return select(STDIN_FILENO + 1, &fds, NULL, NULL, &tv) > 0;
}

// Decode an ANSI escape sequence that follows ESC (already consumed).
static int decode_escape(void) {
    int c2 = byte_available(30) ? read_byte() : -1;
    if (c2 == '[') {
        int c3 = byte_available(30) ? read_byte() : -1;
        if (c3 == '<') {                 // SGR mouse: ESC [ < b ; x ; y M
            int btn = 0;
            int c;
            while ((c = byte_available(30) ? read_byte() : -1) >= 0 && c != 'M' && c != 'm') {
                if (c == ';') { while (byte_available(30) && (c = read_byte()) != 'M' && c != 'm') {} break; }
                if (c >= '0' && c <= '9') btn = btn * 10 + (c - '0');
            }
            if (btn == 64) return TUI_KEY_WHEEL_UP;
            if (btn == 65) return TUI_KEY_WHEEL_DOWN;
            return TUI_KEY_NONE;
        }
        switch (c3) {
            case 'A': return TUI_KEY_UP;
            case 'B': return TUI_KEY_DOWN;
            case '5': if (byte_available(30)) read_byte(); return TUI_KEY_PGUP;
            case '6': if (byte_available(30)) read_byte(); return TUI_KEY_PGDN;
            default:  return TUI_KEY_NONE;
        }
    }
    if (c2 == 'O') {
        int c3 = byte_available(30) ? read_byte() : -1;
        switch (c3) {
            case 'A': return TUI_KEY_UP;
            case 'B': return TUI_KEY_DOWN;
            default:  return TUI_KEY_NONE;
        }
    }
    return TUI_KEY_NONE;
}
#endif

int tui_read_key(char *ch) {
    if (ch) *ch = 0;

#ifdef _WIN32
    return read_win_event(ch);
#else
    int c = read_byte();
    if (c < 0) return TUI_KEY_EOF;

    if (c == 13 || c == 10) return TUI_KEY_ENTER;
    if (c == 8 || c == 127) return TUI_KEY_BACKSPACE;
    if (c == 9) return TUI_KEY_TAB;
    if (c == 3) return TUI_KEY_CTRL_C;
    if (c == 16) return TUI_KEY_UP;     // Ctrl+P
    if (c == 14) return TUI_KEY_DOWN;   // Ctrl+N
    if (c == 27) return decode_escape();

    if (c >= 32 && c < 127) { if (ch) *ch = (char)c; return TUI_KEY_CHAR; }
    return TUI_KEY_NONE;
#endif
}

int tui_read_key_timeout(char *ch, int ms) {
    if (ch) *ch = 0;
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    if (h == INVALID_HANDLE_VALUE) return TUI_KEY_EOF;
    if (WaitForSingleObject(h, (DWORD)ms) != WAIT_OBJECT_0) return TUI_KEY_NONE;
    return read_win_event(ch);
#else
    if (!byte_available(ms)) return TUI_KEY_NONE;
    return tui_read_key(ch);
#endif
}

void tui_clear(void) {
    printf("\033[2J\033[3J\033[H");   // clear screen + scrollback + home
    fflush(stdout);
}

void tui_rule(int width, const char *color) {
    printf("%s", color ? color : TUI_DIM);
    for (int i = 0; i < width; i++) putchar('-');
    printf("%s\n", TUI_RESET);
}

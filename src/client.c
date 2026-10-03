// wschat client - console TUI chat client (entry point for wschat_client).
// Connects to the server, logs in, picks a room and chats; auto-reconnects.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdarg.h>
#include <pthread.h>

#include "common.h"      // platform/socket helpers, constants, logging
#include "ws_frame.h"    // shared WebSocket framing
#include "json_util.h"   // shared JSON field helpers
#include "path_util.h"   // exe-relative data paths
#include "tui.h"         // terminal UI helpers

// base64 for the handshake key, RAND for the random key bytes
#include <openssl/rand.h>

#define SERVER_HOST "127.0.0.1"

#ifdef _WIN32
    #include <direct.h>
    #define MKDIR_ONE(p) _mkdir(p)
    #define SLEEP_MS(ms) Sleep((DWORD)(ms))
#else
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <termios.h>
    #define MKDIR_ONE(p) mkdir(p, 0755)
    #define SLEEP_MS(ms) usleep((useconds_t)((ms) * 1000))
#endif

// ---- Client-side local store (separate from server data) ----
#define CLIENT_DATA_DIR "client_data"
#define CLIENT_DB_MAGIC "WSCL"

static void base64_encode(const unsigned char *input, int length, char *output) {
    const char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j;
    for (i = 0, j = 0; i < length; i += 3) {
        uint32_t a = (uint32_t)input[i];
        uint32_t b = (i + 1 < length) ? (uint32_t)input[i + 1] : 0;
        uint32_t c = (i + 2 < length) ? (uint32_t)input[i + 2] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        output[j++] = table[(triple >> 18) & 0x3F];
        output[j++] = table[(triple >> 12) & 0x3F];
        output[j++] = (i + 1 < length) ? table[(triple >> 6) & 0x3F] : '=';
        output[j++] = (i + 2 < length) ? table[triple & 0x3F] : '=';
    }
    output[j] = '\0';
}

static int do_handshake(int fd, const char *host, int port) {
    // Generate a random 16-byte key (RFC 6455 requires an unpredictable key)
    unsigned char key_raw[16];
    RAND_bytes(key_raw, sizeof(key_raw));
    char key_b64[64];
    base64_encode(key_raw, 16, key_b64);

    char request[1024];
    int rlen = snprintf(request, sizeof(request),
        "GET / HTTP/1.1\r\n"
        "Host: %s:%d\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Key: %s\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n",
        host, port, key_b64);

    send(fd, request, rlen, 0);

    // Read response
    char resp[4096];
    int n = recv(fd, resp, sizeof(resp) - 1, 0);
    if (n <= 0) return -1;
    resp[n] = '\0';

    return strstr(resp, "101 Switching Protocols") ? 0 : -1;
}

static char g_nickname[64] = "User";

// Set by the recv thread when the socket is closed.
static volatile int g_disconnected = 0;
// Set when the user logs out (return to the auth screen).
static volatile int g_logged_out = 0;

// Format an incoming JSON message for display, distinguishing the sender.
static void display_message(const char *json) {
    char type[32] = {0};
    if (json_get_string(json, "type", type, sizeof(type)) != 0) {
        printf("%s\n", json);
        return;
    }

    if (strcmp(type, "MESSAGE") == 0) {
        char from[64] = {0}, room[64] = {0}, content[MAX_MSG_LEN] = {0};
        json_get_string(json, "from", from, sizeof(from));
        json_get_string(json, "room", room, sizeof(room));
        json_get_string(json, "content", content, sizeof(content));
        if (strcmp(from, g_nickname) == 0)
            printf("\r[%s] (you) %s: %s\n", room, from, content);
        else
            printf("\r[%s] %s: %s\n", room, from, content);
    }
    else if (strcmp(type, "JOINED") == 0) {
        char room[64] = {0}, users[2048] = {0};
        json_get_string(json, "room", room, sizeof(room));
        json_get_raw(json, "users", users, sizeof(users));
        printf("\r* Joined room '%s'. Online: %s\n", room, users);
    }
    else if (strcmp(type, "USER_JOIN") == 0) {
        char user[64] = {0};
        json_get_string(json, "user", user, sizeof(user));
        printf("\r* %s joined the room\n", user);
    }
    else if (strcmp(type, "USER_LEAVE") == 0) {
        char user[64] = {0};
        json_get_string(json, "user", user, sizeof(user));
        printf("\r* %s left the room\n", user);
    }
    else if (strcmp(type, "USER_LIST") == 0) {
        char users[2048] = {0};
        json_get_raw(json, "users", users, sizeof(users));
        printf("\r* Online: %s\n", users);
    }
    else if (strcmp(type, "PONG") == 0) {
        printf("\r* pong\n");
    }
    else if (strcmp(type, "LOGIN_OK") == 0) {
        char u[64] = {0};
        json_get_string(json, "username", u, sizeof(u));
        printf("\r* Logged in as '%s'\n", u);
    }
    else if (strcmp(type, "LOGIN_FAIL") == 0) {
        char m[256] = {0};
        json_get_string(json, "msg", m, sizeof(m));
        printf("\r! Login failed: %s\n", m);
    }
    else if (strcmp(type, "REGISTER_OK") == 0) {
        char u[64] = {0};
        json_get_string(json, "username", u, sizeof(u));
        printf("\r* Account created for '%s'\n", u);
    }
    else if (strcmp(type, "REGISTER_FAIL") == 0) {
        char m[256] = {0};
        json_get_string(json, "msg", m, sizeof(m));
        printf("\r! Registration failed: %s\n", m);
    }
    else if (strcmp(type, "JOIN_FAIL") == 0) {
        char m[256] = {0};
        json_get_string(json, "msg", m, sizeof(m));
        printf("\r! Cannot join: %s\n", m);
    }
    else if (strcmp(type, "ERROR") == 0) {
        char m[256] = {0};
        json_get_string(json, "msg", m, sizeof(m));
        printf("\r! Error: %s\n", m);
    }
    else {
        printf("%s\n", json);
    }
}

// Send a text frame containing a JSON string.
// Serializes socket writes (chat thread + heartbeat thread).
static pthread_mutex_t g_send_lock = PTHREAD_MUTEX_INITIALIZER;

static int ws_send_json(int fd, const char *json) {
    uint8_t ws_buf[MAX_MSG_LEN * 2 + 16];
    int len = ws_frame_encode(WS_OPCODE_TEXT, (const uint8_t *)json, strlen(json),
                              true, ws_buf, sizeof(ws_buf));
    if (len <= 0) return -1;
    pthread_mutex_lock(&g_send_lock);
    int rc = send(fd, (char *)ws_buf, len, 0);
    pthread_mutex_unlock(&g_send_lock);
    return rc;
}

// Read exactly one text frame (synchronous). Returns 0 on success.
static int ws_recv_one(int fd, char *out, size_t out_size) {
    uint8_t buf[65536];
    size_t have = 0;

    for (;;) {
        int n = recv(fd, (char *)buf + have, sizeof(buf) - have, 0);
        if (n <= 0) return -1;
        have += (size_t)n;

        ws_frame_t frame;
        memset(&frame, 0, sizeof(frame));
        int consumed = ws_frame_decode(buf, have, &frame);
        if (consumed < 0) return -1;
        if (consumed == 0) continue;   // partial frame: read more

        if (frame.opcode == WS_OPCODE_TEXT && frame.payload) {
            size_t c = (frame.payload_len < out_size - 1) ? (size_t)frame.payload_len : out_size - 1;
            memcpy(out, frame.payload, c);
            out[c] = '\0';
        }
        ws_frame_free(&frame);
        return 0;
    }
}

// Read a trimmed line from stdin. Returns 0 on success, -1 on EOF.
static int read_line(const char *prompt, char *out, size_t out_size) {
    printf("%s", prompt);
    fflush(stdout);
    if (!fgets(out, (int)out_size, stdin)) return -1;
    out[strcspn(out, "\r\n")] = '\0';
    return 0;
}

// Send a JSON request and display the single response frame.
static int request(int fd, const char *json, char *resp, size_t resp_size) {
    if (ws_send_json(fd, json) < 0) return -1;
    if (ws_recv_one(fd, resp, resp_size) != 0) return -1;
    display_message(resp);
    return 0;
}

static int do_login(int fd, const char *user, const char *pass) {
    char json[MAX_MSG_LEN + 256];
    snprintf(json, sizeof(json),
        "{\"type\":\"LOGIN\",\"username\":\"%s\",\"password\":\"%s\"}", user, pass);
    char resp[MAX_MSG_LEN];
    if (request(fd, json, resp, sizeof(resp)) != 0) return -1;
    char type[32] = {0};
    json_get_string(resp, "type", type, sizeof(type));
    return strcmp(type, "LOGIN_OK") == 0 ? 0 : -1;
}

static int do_register(int fd, const char *user, const char *pass) {
    char json[MAX_MSG_LEN + 256];
    snprintf(json, sizeof(json),
        "{\"type\":\"REGISTER\",\"username\":\"%s\",\"password\":\"%s\"}", user, pass);
    char resp[MAX_MSG_LEN];
    if (request(fd, json, resp, sizeof(resp)) != 0) return -1;
    char type[32] = {0};
    json_get_string(resp, "type", type, sizeof(type));
    return strcmp(type, "REGISTER_OK") == 0 ? 0 : -1;
}

// ---- Local client profile (binary, kept separate from server data) ----
typedef struct {
    char username[64];
    char room[64];
} client_profile_t;

static void client_profile_save(const client_profile_t *p) {
    char dir[1024], path[1100];
    data_dir_path(CLIENT_DATA_DIR, dir, sizeof(dir));
    MKDIR_ONE(dir);
    snprintf(path, sizeof(path), "%s/client.dat", dir);
    FILE *f = fopen(path, "wb");
    if (!f) return;
    uint8_t header[8];
    memcpy(header, CLIENT_DB_MAGIC, 4);
    header[4] = 1; header[5] = 0; header[6] = 0; header[7] = 0;
    fwrite(header, 1, 8, f);
    char u[64] = {0}, r[64] = {0};
    snprintf(u, sizeof(u), "%s", p->username);
    snprintf(r, sizeof(r), "%s", p->room);
    fwrite(u, 1, 64, f);
    fwrite(r, 1, 64, f);
    fclose(f);
}

static int client_profile_load(client_profile_t *p) {
    char dir[1024], path[1100];
    data_dir_path(CLIENT_DATA_DIR, dir, sizeof(dir));
    snprintf(path, sizeof(path), "%s/client.dat", dir);
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    uint8_t header[8];
    if (fread(header, 1, 8, f) != 8 || memcmp(header, CLIENT_DB_MAGIC, 4) != 0) {
        fclose(f);
        return -1;
    }
    char u[64] = {0}, r[64] = {0};
    if (fread(u, 1, 64, f) != 64 || fread(r, 1, 64, f) != 64) {
        fclose(f);
        return -1;
    }
    u[63] = '\0';
    r[63] = '\0';
    memset(p, 0, sizeof(*p));
    snprintf(p->username, sizeof(p->username), "%s", u);
    snprintf(p->room, sizeof(p->room), "%s", r);
    fclose(f);
    return 0;
}

// ---- Room list UI ----
typedef struct {
    char name[64];
    char desc[160];
    int  members;
    int  has_code;
} room_info_t;

static int parse_room_list(const char *json, room_info_t *out, int max) {
    const char *p = strstr(json, "\"rooms\"");
    if (!p) return 0;
    p = strchr(p, '[');
    if (!p) return 0;

    int n = 0;
    while (n < max) {
        const char *obj = strchr(p, '{');
        if (!obj) break;
        const char *end = strchr(obj, '}');
        if (!end) break;

        char buf[512];
        size_t len = (size_t)(end - obj) + 1;
        if (len >= sizeof(buf)) len = sizeof(buf) - 1;
        memcpy(buf, obj, len);
        buf[len] = '\0';

        memset(&out[n], 0, sizeof(out[n]));
        json_get_string(buf, "name", out[n].name, sizeof(out[n].name));
        json_get_string(buf, "desc", out[n].desc, sizeof(out[n].desc));
        const char *mp = strstr(buf, "\"members\"");
        if (mp) {
            mp = strchr(mp, ':');
            if (mp) out[n].members = atoi(mp + 1);
        }
        out[n].has_code = (strstr(buf, "\"code\":true") != NULL);
        n++;
        p = end + 1;
    }
    return n;
}

static void render_room_list(const room_info_t *rooms, int n, const char *username) {
    tui_clear();

    // Fixed column layout so the borders line up.
    const char *B = TUI_BLUE, *R = TUI_RESET;
    const char *border = "+----+--------------+---------+------+------------------------------------+";
    const char *sep    = "+====+==============+=========+======+====================================+";

    printf("%s%s", TUI_CYAN, TUI_BOLD);
    printf("%s\n", border);
    printf("|  AVAILABLE ROOMS%*suser: %-10s |\n", 40, "", username);
    printf("%s\n", sep);
    printf("|  # | ROOM         | MEMBERS | CODE | DESCRIPTION                        |\n");
    printf("%s%s\n", TUI_BLUE, border);
    printf("%s", R);

    for (int i = 0; i < n; i++) {
        printf("%s|%s %s%2d%s %s|%s %s%-12s%s ", B, R, TUI_YELLOW, i + 1, R, B, R,
               TUI_CYAN, rooms[i].name, R);
        printf("%s|%s %7d %s|%s %-4s %s|%s %-34s %s|%s\n",
               B, R, rooms[i].members, B, R,
               rooms[i].has_code ? "yes" : "-", B, R,
               rooms[i].desc, B, R);
    }

    printf("%s%s\n%s", TUI_BLUE, border, R);
    printf("\n");
}

// Interactively pick a room and join it. On success writes the room name to
// joined. Returns 0 on joined, -1 if the user gave up.
static int await_response(char *out, size_t n);

// Fetch the room list into rooms[]. Returns 0 on success, -1 on error.
static int fetch_rooms(int fd, room_info_t *rooms, int *n_out) {
    char resp[16384];
    if (ws_send_json(fd, "{\"type\":\"ROOMS\"}") < 0) return -1;
    if (await_response(resp, sizeof(resp)) != 0) return -1;
    if (strstr(resp, "\"DISCONNECTED\"")) return -1;
    *n_out = parse_room_list(resp, rooms, 32);
    return 0;
}

// Returns 0 = joined, 1 = user quit, -1 = disconnected/error.
static int select_room(int fd, char *joined, size_t joined_size) {
    room_info_t rooms[32];
    int n = 0;

    for (;;) {
        if (fetch_rooms(fd, rooms, &n) != 0) return -1;
        if (n <= 0) {
            printf("No rooms available. Press Enter to refresh, or q to quit: ");
            fflush(stdout);
            char s[16];
            if (!fgets(s, sizeof(s), stdin)) return 1;
            if (s[0] == 'q' || s[0] == 'Q') return 1;
            continue;
        }
        render_room_list(rooms, n, g_nickname);

        char sel[16];
        if (read_line("Select room # (q to quit): ", sel, sizeof(sel)) != 0) return 1;
        if (sel[0] == 'q' || sel[0] == 'Q') return 1;

        int idx = atoi(sel) - 1;
        if (idx < 0 || idx >= n) {
            printf("%sInvalid selection.%s\n", TUI_RED, TUI_RESET);
            continue;
        }

        char code[64] = {0};
        if (rooms[idx].has_code) {
            char tmp[64];
            if (read_line("Room code: ", tmp, sizeof(tmp)) != 0) return 1;
            snprintf(code, sizeof(code), "%s", tmp);
        }

        char join[MAX_MSG_LEN];
        snprintf(join, sizeof(join),
                 "{\"type\":\"JOIN\",\"room\":\"%s\",\"code\":\"%s\"}",
                 rooms[idx].name, code);
        if (ws_send_json(fd, join) < 0) return -1;

        char jresp[4096];
        if (await_response(jresp, sizeof(jresp)) != 0) return -1;
        if (strstr(jresp, "\"DISCONNECTED\"")) return -1;
        display_message(jresp);

        char type[32] = {0};
        json_get_string(jresp, "type", type, sizeof(type));
        if (strcmp(type, "JOINED") == 0) {
            snprintf(joined, joined_size, "%s", rooms[idx].name);
            return 0;
        }

        printf("%sPress Enter to try another room...%s", TUI_DIM, TUI_RESET);
        char dummy[16];
        if (!fgets(dummy, sizeof(dummy), stdin)) return 1;
    }
}

// Draw a title header box.
static void tui_header(const char *title) {
    tui_clear();
    printf("%s%s", TUI_CYAN, TUI_BOLD);
    tui_rule(60, TUI_CYAN);
    printf("  %s\n", title);
    tui_rule(60, TUI_CYAN);
    printf("%s", TUI_RESET);
}

// Read a line with echo disabled (password entry). Falls back to normal input
// when stdin is not a console (e.g. piped input).
static int read_password(const char *prompt, char *out, size_t out_size) {
    printf("%s", prompt);
    fflush(stdout);
#ifdef _WIN32
    HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    int mask = (h != INVALID_HANDLE_VALUE) && GetConsoleMode(h, &mode);
    if (mask) SetConsoleMode(h, mode & ~(DWORD)ENABLE_ECHO_INPUT);
#else
    struct termios oldt, newt;
    int mask = (tcgetattr(STDIN_FILENO, &oldt) == 0);
    if (mask) {
        newt = oldt;
        newt.c_lflag &= ~(tcflag_t)ECHO;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
#endif
    int rc = fgets(out, (int)out_size, stdin) ? 0 : -1;
#ifdef _WIN32
    if (mask) { SetConsoleMode(h, mode); printf("\n"); }
#else
    if (mask) { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); printf("\n"); }
#endif
    if (rc == 0) out[strcspn(out, "\r\n")] = '\0';
    return rc;
}

static void pause_enter(void) {
    printf("  %sPress Enter to continue...%s", TUI_DIM, TUI_RESET);
    fflush(stdout);
    char d[8];
    if (!fgets(d, sizeof(d), stdin)) { /* EOF */ }
}

// Login / Register TUI. Returns 1 when authenticated, 0 if the user quits.
static int auth_flow(int fd, char *username, size_t usize,
                     char *password, size_t psize) {
    for (;;) {
        tui_header("WEBSOCKET CHAT  -  SIGN IN");
        printf("  %s[1]%s Login\n", TUI_YELLOW, TUI_RESET);
        printf("  %s[2]%s Register\n", TUI_YELLOW, TUI_RESET);
        printf("  %s[Q]%s Quit\n", TUI_YELLOW, TUI_RESET);
        tui_rule(60, TUI_DIM);
        printf("\n");

        char choice[16];
        if (read_line("  Choose > ", choice, sizeof(choice)) != 0) return 0;
        if (choice[0] == 'q' || choice[0] == 'Q') return 0;

        if (strcmp(choice, "1") == 0) {
            tui_header("LOGIN");
            if (read_line("  Username: ", username, usize) != 0) return 0;
            if (read_password("  Password: ", password, psize) != 0) return 0;
            if (do_login(fd, username, password) == 0) return 1;
            printf("\n");
            pause_enter();
        } else if (strcmp(choice, "2") == 0) {
            tui_header("REGISTER");
            if (read_line("  New username (3-31 chars, letters/digits/_): ",
                          username, usize) != 0) return 0;
            if (read_password("  New password (min 4): ", password, psize) != 0) return 0;
            char confirm[64];
            if (read_password("  Confirm password: ", confirm, sizeof(confirm)) != 0) return 0;
            if (strcmp(password, confirm) != 0) {
                printf("\n  %sPasswords do not match.%s\n", TUI_RED, TUI_RESET);
                pause_enter();
                continue;
            }
            if (do_register(fd, username, password) == 0) {
                if (do_login(fd, username, password) == 0) return 1;
            }
            printf("\n");
            pause_enter();
        } else {
            printf("  %sInvalid choice.%s\n", TUI_RED, TUI_RESET);
        }
    }
}

// =====================================================================
//  Chat view (full-screen TUI with a user panel)
// =====================================================================

#define CHAT_MAX_LINES 2000
#define CHAT_LINE_LEN  1024
#define CHAT_MAX_USERS 64

#define CHAT_RESULT_LEAVE   0
#define CHAT_RESULT_EXIT    1
#define CHAT_RESULT_DISCONN 2
#define CHAT_RESULT_LOGOUT  3

#define CHAT_KIND_NORMAL 0
#define CHAT_KIND_SYSTEM 1
#define CHAT_KIND_OWN    2
#define CHAT_KIND_ERROR  3

typedef struct {
    char lines[CHAT_MAX_LINES][CHAT_LINE_LEN];
    int  kinds[CHAT_MAX_LINES];
    int  line_count;
    char users[CHAT_MAX_USERS][64];
    int  user_count;
    char room[64];
    volatile int mode;         // 0 = selecting, 1 = chatting
    int  msg_scroll;           // lines scrolled up from the bottom
    int  user_scroll;
    int  focus;                // 0 = messages, 1 = users
    char input[CHAT_LINE_LEN];
    int  input_len;
} chat_state_t;

static chat_state_t   g_chat;
static pthread_mutex_t g_chat_lock = PTHREAD_MUTEX_INITIALIZER;

// ---- response slot used while picking rooms ----
static char            g_resp[16384];
static volatile int    g_resp_ready = 0;
static pthread_mutex_t g_resp_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  g_resp_cond = PTHREAD_COND_INITIALIZER;

static void deliver_response(const char *json) {
    pthread_mutex_lock(&g_resp_lock);
    snprintf(g_resp, sizeof(g_resp), "%s", json);
    g_resp_ready = 1;
    pthread_cond_signal(&g_resp_cond);
    pthread_mutex_unlock(&g_resp_lock);
}

static int await_response(char *out, size_t n) {
    pthread_mutex_lock(&g_resp_lock);
    while (!g_resp_ready) pthread_cond_wait(&g_resp_cond, &g_resp_lock);
    int cap = (n > 0) ? (int)n - 1 : 0;
    snprintf(out, n, "%.*s", cap, g_resp);
    g_resp_ready = 0;
    pthread_mutex_unlock(&g_resp_lock);
    return 0;
}

// ---- chat log ----
static void chat_log(int kind, const char *line) {
    pthread_mutex_lock(&g_chat_lock);
    int idx = g_chat.line_count % CHAT_MAX_LINES;
    size_t n = strlen(line);
    if (n >= CHAT_LINE_LEN) n = CHAT_LINE_LEN - 1;
    memcpy(g_chat.lines[idx], line, n);
    g_chat.lines[idx][n] = '\0';
    g_chat.kinds[idx] = kind;
    g_chat.line_count++;
    if (g_chat.mode == 1 && !tui_is_tty()) {
        printf("\r%s\n> ", line);
        fflush(stdout);
    }
    pthread_mutex_unlock(&g_chat_lock);
}

static volatile int g_room_closed = 0;   // set when the server closes our room

static void chat_reset_view(void) {
    g_room_closed = 0;
    pthread_mutex_lock(&g_chat_lock);
    g_chat.line_count = 0;
    g_chat.user_count = 0;
    g_chat.msg_scroll = 0;
    g_chat.user_scroll = 0;
    g_chat.focus = 0;
    g_chat.input_len = 0;
    g_chat.input[0] = '\0';
    pthread_mutex_unlock(&g_chat_lock);
}

static int chat_find_user(const char *name) {
    for (int i = 0; i < g_chat.user_count; i++)
        if (strcmp(g_chat.users[i], name) == 0) return i;
    return -1;
}

static void chat_add_user(const char *name) {
    pthread_mutex_lock(&g_chat_lock);
    if (g_chat.user_count < CHAT_MAX_USERS && chat_find_user(name) < 0) {
        snprintf(g_chat.users[g_chat.user_count], 64, "%s", name);
        g_chat.user_count++;
    }
    pthread_mutex_unlock(&g_chat_lock);
}

static void chat_remove_user(const char *name) {
    pthread_mutex_lock(&g_chat_lock);
    int i = chat_find_user(name);
    if (i >= 0) {
        for (int j = i; j < g_chat.user_count - 1; j++)
            strcpy(g_chat.users[j], g_chat.users[j + 1]);
        g_chat.user_count--;
    }
    pthread_mutex_unlock(&g_chat_lock);
}

static void chat_set_users(const char *arr) {
    pthread_mutex_lock(&g_chat_lock);
    g_chat.user_count = 0;
    const char *p = arr;
    while (p && *p) {
        p = strchr(p, '"');
        if (!p) break;
        p++;
        const char *e = strchr(p, '"');
        if (!e) break;
        size_t n = (size_t)(e - p);
        if (n >= 64) n = 63;
        if (g_chat.user_count < CHAT_MAX_USERS) {
            memcpy(g_chat.users[g_chat.user_count], p, n);
            g_chat.users[g_chat.user_count][n] = '\0';
            g_chat.user_count++;
        }
        p = e + 1;
    }
    pthread_mutex_unlock(&g_chat_lock);
}

// ---- server frame dispatch ----
static void render_chat(void);
static void chat_notify(void);   // redraw if a chat TUI is active

static void on_frame(const char *json) {
    char type[32] = {0};
    if (json_get_string(json, "type", type, sizeof(type)) != 0) return;

    if (strcmp(type, "ROOM_LIST") == 0 || strcmp(type, "JOIN_FAIL") == 0) {
        deliver_response(json);
        return;
    }
    if (strcmp(type, "JOINED") == 0) {
        char room[64] = {0}, users[8192] = {0};
        json_get_string(json, "room", room, sizeof(room));
        json_get_raw(json, "users", users, sizeof(users));
        pthread_mutex_lock(&g_chat_lock);
        snprintf(g_chat.room, sizeof(g_chat.room), "%s", room);
        pthread_mutex_unlock(&g_chat_lock);
        chat_set_users(users);
        deliver_response(json);
        return;
    }

    char line[CHAT_LINE_LEN];
    if (strcmp(type, "MESSAGE") == 0) {
        char from[64] = {0}, room[64] = {0}, content[512] = {0};
        json_get_string(json, "from", from, sizeof(from));
        json_get_string(json, "room", room, sizeof(room));
        json_get_string(json, "content", content, sizeof(content));
        if (strcmp(from, g_nickname) == 0)
            snprintf(line, sizeof(line), "[%s] (you) %s: %s", room, from, content);
        else
            snprintf(line, sizeof(line), "[%s] %s: %s", room, from, content);
        chat_log(strcmp(from, g_nickname) == 0 ? CHAT_KIND_OWN : CHAT_KIND_NORMAL, line);
    } else if (strcmp(type, "USER_JOIN") == 0) {
        char u[64] = {0};
        json_get_string(json, "user", u, sizeof(u));
        chat_add_user(u);
        snprintf(line, sizeof(line), "* %s joined", u);
        chat_log(CHAT_KIND_SYSTEM, line);
    } else if (strcmp(type, "USER_LEAVE") == 0) {
        char u[64] = {0};
        json_get_string(json, "user", u, sizeof(u));
        chat_remove_user(u);
        snprintf(line, sizeof(line), "* %s left", u);
        chat_log(CHAT_KIND_SYSTEM, line);
    } else if (strcmp(type, "USER_LIST") == 0) {
        char users[8192] = {0};
        json_get_raw(json, "users", users, sizeof(users));
        chat_set_users(users);
    } else if (strcmp(type, "PONG") == 0) {
        // keepalive reply; ignored (no chat spam)
    } else if (strcmp(type, "LEFT") == 0) {
        // Server confirmed we left the room; already back at room selection.
    } else if (strcmp(type, "LOGGED_OUT") == 0) {
        g_logged_out = 1;
    } else if (strcmp(type, "ROOM_CLOSED") == 0) {
        char room[64] = {0};
        json_get_string(json, "room", room, sizeof(room));
        snprintf(line, sizeof(line), "! Room '%s' was closed by the server.", room);
        chat_log(CHAT_KIND_ERROR, line);
        g_room_closed = 1;
    } else if (strcmp(type, "ERROR") == 0) {
        char m[256] = {0};
        json_get_string(json, "msg", m, sizeof(m));
        snprintf(line, sizeof(line), "! %s", m);
        chat_log(CHAT_KIND_ERROR, line);
    } else {
        snprintf(line, sizeof(line), "> %s", json);
        chat_log(CHAT_KIND_NORMAL, line);
    }

    // Push an immediate redraw so incoming events appear without user input.
    chat_notify();
}

static int          g_fd = -1;
static volatile int g_recv_running = 1;

static void *recv_loop(void *arg) {
    (void)arg;
    static uint8_t buf[1 << 20];   // carry + newly received bytes
    size_t carry = 0;

    while (g_recv_running) {
        int n = recv(g_fd, (char *)buf + carry, sizeof(buf) - carry, 0);
        if (n <= 0) break;
        size_t total = carry + (size_t)n;

        size_t pos = 0;
        while (pos < total) {
            ws_frame_t frame;
            memset(&frame, 0, sizeof(frame));
            int consumed = ws_frame_decode(buf + pos, total - pos, &frame);
            if (consumed < 0) { pos = total; break; }   // protocol error: drop
            if (consumed == 0) break;                   // need more data
            if (frame.opcode == WS_OPCODE_TEXT && frame.payload) {
                on_frame((const char *)frame.payload);
            }
            ws_frame_free(&frame);
            pos += (size_t)consumed;
        }

        carry = total - pos;
        if (carry > 0 && pos > 0) memmove(buf, buf + pos, carry);
    }
    g_disconnected = 1;
    deliver_response("{\"type\":\"DISCONNECTED\"}");
    return NULL;
}

// Keepalive: sends PING every HEARTBEAT_SECS so the server does not idle us out.
#define HEARTBEAT_SECS 25
static volatile int g_hb_stop = 0;

static void *heartbeat_loop(void *arg) {
    (void)arg;
    int elapsed = 0;
    while (!g_hb_stop) {
        SLEEP_MS(1000);
        if (g_hb_stop) break;
        if (++elapsed >= HEARTBEAT_SECS) {
            elapsed = 0;
            ws_send_json(g_fd, "{\"type\":\"PING\"}");
        }
    }
    return NULL;
}

// ---- rendering ----
static char g_frame[1 << 16];
static int  g_frame_len;

static void fb_puts(const char *s) {
    int n = (int)strlen(s);
    if (g_frame_len + n < (int)sizeof(g_frame) - 1) {
        memcpy(g_frame + g_frame_len, s, n);
        g_frame_len += n;
    }
}
static void fb_printf(const char *fmt, ...) {
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    fb_puts(tmp);
}
static void fb_flush(void) {
    if (g_frame_len > 0) fwrite(g_frame, 1, g_frame_len, stdout);
    fflush(stdout);
}

static void fb_hline(int L, int P) {
    char buf[2048];
    int n = 0;
    buf[n++] = '+';
    for (int i = 0; i < L && n < (int)sizeof(buf) - 1; i++) buf[n++] = '-';
    buf[n++] = '+';
    for (int i = 0; i < P && n < (int)sizeof(buf) - 1; i++) buf[n++] = '-';
    buf[n++] = '+';
    buf[n] = '\0';
    fb_puts(TUI_BLUE);
    fb_puts(buf);
    fb_puts(TUI_RESET);
}

// Print text clipped/padded to a fixed visible width, optionally colored.
static void fb_field(const char *text, int width, const char *color) {
    static char buf[2048];
    if (width > (int)sizeof(buf) - 1) width = (int)sizeof(buf) - 1;
    int n = 0;
    if (text) {
        while (text[n] && n < width) { buf[n] = text[n]; n++; }
    }
    int len = n;
    for (; n < width; n++) buf[n] = ' ';
    buf[n] = '\0';
    (void)len;
    if (color) fb_puts(color);
    fb_puts(buf);
    if (color) fb_puts(TUI_RESET);
}

// Full-screen redraw of the chat view. Holds no lock on entry.
static void render_chat(void) {
    if (!tui_is_tty()) return;

    int cols, rows;
    tui_size(&cols, &rows);
    if (cols < 44) cols = 44;
    if (rows < 9) rows = 9;

    int P = 22;                      // user panel width
    if (P > cols / 3) P = cols / 3;
    if (P < 8) P = 8;
    int L = cols - 3 - P;            // message area width
    if (L < 12) { L = 12; P = cols - 3 - L; if (P < 8) P = 8; }

    int body_top = 4;
    int body_h = rows - 5;           // rows 4..rows-2
    if (body_h < 1) body_h = 1;

    pthread_mutex_lock(&g_chat_lock);

    g_frame_len = 0;
    fb_puts("\033[H");

    // Row 1: top border
    fb_printf("\033[1;1H\033[2K");
    fb_hline(L, P);

    // Row 2: title bar
    fb_printf("\033[2;1H\033[2K");
    fb_puts(TUI_BLUE "|" TUI_RESET);
    char t1[256];
    snprintf(t1, sizeof(t1), " WebSocket Chat   room: %s", g_chat.room);
    fb_field(t1, L, TUI_CYAN TUI_BOLD);
    fb_puts(TUI_BLUE "|" TUI_RESET);
    char t2[64];
    snprintf(t2, sizeof(t2), " USERS (%d)", g_chat.user_count);
    fb_field(t2, P, g_chat.focus == 1 ? TUI_YELLOW TUI_BOLD : TUI_CYAN TUI_BOLD);
    fb_puts(TUI_BLUE "|" TUI_RESET);

    // Row 3: separator
    fb_printf("\033[3;1H\033[2K");
    fb_hline(L, P);

    // Body rows
    int total = g_chat.line_count;
    int bottom_idx = total - 1 - g_chat.msg_scroll;
    int top_idx = bottom_idx - (body_h - 1);
    if (top_idx < 0) top_idx = 0;

    for (int r = 0; r < body_h; r++) {
        fb_printf("\033[%d;1H\033[2K", body_top + r);
        fb_puts(TUI_BLUE "|" TUI_RESET);

        const char *lt = "";
        const char *lc = NULL;
        int mi = top_idx + r;
        if (mi >= 0 && mi < total) {
            int slot = mi % CHAT_MAX_LINES;
            lt = g_chat.lines[slot];
            switch (g_chat.kinds[slot]) {
                case CHAT_KIND_SYSTEM: lc = TUI_YELLOW; break;
                case CHAT_KIND_OWN:    lc = TUI_GREEN;  break;
                case CHAT_KIND_ERROR:  lc = TUI_RED;    break;
                default:               lc = NULL;       break;
            }
        }
        fb_field(lt, L, lc);
        fb_puts(TUI_BLUE "|" TUI_RESET);

        int ui = g_chat.user_scroll + r;
        if (ui >= 0 && ui < g_chat.user_count) {
            int own = (strcmp(g_chat.users[ui], g_nickname) == 0);
            char ubuf[96];
            snprintf(ubuf, sizeof(ubuf), " %s%s", own ? "* " : "- ", g_chat.users[ui]);
            fb_field(ubuf, P, own ? TUI_GREEN : TUI_CYAN);
        } else {
            fb_field("", P, NULL);
        }
        fb_puts(TUI_BLUE "|" TUI_RESET);
    }

    // Bottom separator
    fb_printf("\033[%d;1H\033[2K", rows - 1);
    fb_hline(L, P);

    // Input row
    fb_printf("\033[%d;1H\033[2K", rows);
    fb_puts(TUI_BLUE "|" TUI_RESET);
    char in[CHAT_LINE_LEN + 8];
    snprintf(in, sizeof(in), "> %s", g_chat.input);
    fb_field(in, L + 1 + P, g_chat.focus == 1 ? TUI_DIM : TUI_BOLD);
    fb_puts(TUI_BLUE "|" TUI_RESET);

    // Cursor at the end of the typed text
    fb_printf("\033[%d;%dH", rows, 4 + g_chat.input_len);

    fb_flush();
    pthread_mutex_unlock(&g_chat_lock);
}

// Redraw the chat TUI if it is currently active (called from the recv thread).
static void chat_notify(void) {
    if (g_chat.mode == 1 && tui_is_tty()) render_chat();
}

static void send_json_str(const char *json) {
    ws_send_json(g_fd, json);
}

// Full-screen interactive chat. Returns CHAT_RESULT_LEAVE or CHAT_RESULT_EXIT.
static int chat_run_tty(void) {
    tui_raw_enable();

    for (;;) {
        render_chat();

        char ch = 0;
        int key = tui_read_key(&ch);

        if (g_disconnected) {
            tui_raw_disable();
            return CHAT_RESULT_DISCONN;
        }

        if (g_room_closed) {
            // The server deleted our room; go back to room selection.
            tui_raw_disable();
            return CHAT_RESULT_LEAVE;
        }

        int cols, rows;
        tui_size(&cols, &rows);
        int body_h = (rows - 1) - 2 + 1;
        if (body_h < 1) body_h = 1;

        if (key == TUI_KEY_CTRL_C || key == TUI_KEY_EOF) {
            send_json_str("{\"type\":\"LEAVE\"}");
            tui_raw_disable();
            return CHAT_RESULT_EXIT;
        }
        if (key == TUI_KEY_TAB) {
            pthread_mutex_lock(&g_chat_lock);
            g_chat.focus = !g_chat.focus;
            pthread_mutex_unlock(&g_chat_lock);
            continue;
        }
        if (key == TUI_KEY_PGUP || key == TUI_KEY_WHEEL_UP) {
            pthread_mutex_lock(&g_chat_lock);
            int step = (key == TUI_KEY_PGUP) ? body_h : 3;
            if (g_chat.focus == 0) g_chat.msg_scroll += step;
            else if (g_chat.user_scroll > 0) { g_chat.user_scroll -= step; if (g_chat.user_scroll < 0) g_chat.user_scroll = 0; }
            pthread_mutex_unlock(&g_chat_lock);
            continue;
        }
        if (key == TUI_KEY_PGDN || key == TUI_KEY_WHEEL_DOWN) {
            pthread_mutex_lock(&g_chat_lock);
            int step = (key == TUI_KEY_PGDN) ? body_h : 3;
            if (g_chat.focus == 0) {
                g_chat.msg_scroll -= step;
                if (g_chat.msg_scroll < 0) g_chat.msg_scroll = 0;
            } else {
                int maxs = g_chat.user_count - 1;
                g_chat.user_scroll += step;
                if (g_chat.user_scroll > maxs) g_chat.user_scroll = maxs < 0 ? 0 : maxs;
            }
            pthread_mutex_unlock(&g_chat_lock);
            continue;
        }
        if (key == TUI_KEY_UP) {
            pthread_mutex_lock(&g_chat_lock);
            if (g_chat.focus == 0) g_chat.msg_scroll++;
            else if (g_chat.user_scroll > 0) g_chat.user_scroll--;
            pthread_mutex_unlock(&g_chat_lock);
            continue;
        }
        if (key == TUI_KEY_DOWN) {
            pthread_mutex_lock(&g_chat_lock);
            if (g_chat.focus == 0) {
                if (g_chat.msg_scroll > 0) g_chat.msg_scroll--;
            } else {
                g_chat.user_scroll++;
            }
            pthread_mutex_unlock(&g_chat_lock);
            continue;
        }
        if (key == TUI_KEY_BACKSPACE) {
            pthread_mutex_lock(&g_chat_lock);
            if (g_chat.input_len > 0) {
                g_chat.input[--g_chat.input_len] = '\0';
            }
            pthread_mutex_unlock(&g_chat_lock);
            continue;
        }
        if (key == TUI_KEY_ENTER) {
            char line[CHAT_LINE_LEN];
            pthread_mutex_lock(&g_chat_lock);
            snprintf(line, sizeof(line), "%s", g_chat.input);
            g_chat.input_len = 0;
            g_chat.input[0] = '\0';
            pthread_mutex_unlock(&g_chat_lock);

            if (line[0] == '/') {
                if (strcmp(line, "/quit") == 0 || strcmp(line, "/leave") == 0) {
                    send_json_str("{\"type\":\"LEAVE\"}");
                    tui_raw_disable();
                    return CHAT_RESULT_LEAVE;
                }
                if (strcmp(line, "/exit") == 0) {
                    send_json_str("{\"type\":\"LEAVE\"}");
                    tui_raw_disable();
                    return CHAT_RESULT_EXIT;
                }
                if (strcmp(line, "/logout") == 0) {
                    send_json_str("{\"type\":\"LOGOUT\"}");
                    tui_raw_disable();
                    return CHAT_RESULT_LOGOUT;
                }
                if (strcmp(line, "/ping") == 0)  { send_json_str("{\"type\":\"PING\"}"); continue; }
                chat_log(CHAT_KIND_ERROR, "! unknown command (try /quit /exit /logout /ping)");
                continue;
            }
            if (line[0] != '\0') {
                char esc[CHAT_LINE_LEN * 2];
                json_escape(line, esc, sizeof(esc));
                char json[CHAT_LINE_LEN * 2 + 64];
                snprintf(json, sizeof(json),
                         "{\"type\":\"MESSAGE\",\"content\":\"%s\"}", esc);
                send_json_str(json);
                g_chat.msg_scroll = 0;
            }
            continue;
        }
        if (key == TUI_KEY_CHAR) {
            pthread_mutex_lock(&g_chat_lock);
            if (g_chat.input_len < CHAT_LINE_LEN - 1 && ch >= 32) {
                g_chat.input[g_chat.input_len++] = ch;
                g_chat.input[g_chat.input_len] = '\0';
            }
            pthread_mutex_unlock(&g_chat_lock);
            continue;
        }
    }
}

// Line-based fallback for non-interactive stdin (pipes / tests).
static int chat_run_plain(void) {
    printf("Type a message and press Enter. /quit leaves the room, /logout logs out, /exit quits.\n> ");
    fflush(stdout);
    char line[CHAT_LINE_LEN];
    while (fgets(line, sizeof(line), stdin)) {
        if (g_disconnected) { printf("\nDisconnected from server.\n"); return CHAT_RESULT_DISCONN; }
        if (g_room_closed) { printf("\nRoom was closed by the server.\n"); return CHAT_RESULT_LEAVE; }
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '\0') { printf("> "); fflush(stdout); continue; }
        if (line[0] == '/') {
            if (strcmp(line, "/quit") == 0 || strcmp(line, "/leave") == 0) {
                send_json_str("{\"type\":\"LEAVE\"}");
                return CHAT_RESULT_LEAVE;
            }
            if (strcmp(line, "/exit") == 0) {
                send_json_str("{\"type\":\"LEAVE\"}");
                return CHAT_RESULT_EXIT;
            }
            if (strcmp(line, "/logout") == 0) {
                send_json_str("{\"type\":\"LOGOUT\"}");
                return CHAT_RESULT_LOGOUT;
            }
            if (strcmp(line, "/ping") == 0)  { send_json_str("{\"type\":\"PING\"}"); printf("> "); fflush(stdout); continue; }
            printf("! unknown command\n> ");
            fflush(stdout);
            continue;
        }
        char esc[CHAT_LINE_LEN * 2];
        json_escape(line, esc, sizeof(esc));
        char json[CHAT_LINE_LEN * 2 + 64];
        snprintf(json, sizeof(json), "{\"type\":\"MESSAGE\",\"content\":\"%s\"}", esc);
        send_json_str(json);
        printf("> ");
        fflush(stdout);
    }
    send_json_str("{\"type\":\"LEAVE\"}");
    return CHAT_RESULT_EXIT;
}

static int chat_run(void) {
    if (tui_is_tty()) return chat_run_tty();
    return chat_run_plain();
}

// Draw the disconnected/reconnecting screen (kept inside the TUI).
static void render_reconnect(const char *reason, int attempt, int spinner) {
    static const char spin[] = "|/-\\";
    tui_clear();
    printf("%s%s", TUI_CYAN, TUI_BOLD);
    printf("+--------------------------------------------------------------+\n");
    printf("|  WebSocket Chat  -  DISCONNECTED                              |\n");
    printf("+--------------------------------------------------------------+\n");
    printf("%s", TUI_RESET);
    printf("\n  %s%s%s\n", TUI_YELLOW, reason, TUI_RESET);
    printf("  Reconnecting to %s:%d   %c   (attempt %d)\n",
           SERVER_HOST, SERVER_PORT, spin[spinner & 3], attempt);
    printf("\n  %sPress q to quit%s\n", TUI_DIM, TUI_RESET);
    fflush(stdout);
}

// Wait ~2s while staying in the TUI. Returns 1 if the user wants to quit.
static int reconnect_wait(const char *reason, int attempt) {
    if (!tui_is_tty()) {
        printf("%s. Retrying in 2s (Ctrl+C to quit)...\n", reason);
        SLEEP_MS(2000);
        return 0;
    }
    tui_raw_enable();
    int quit = 0;
    for (int step = 0; step < 10 && !quit; step++) {   // 10 x 200ms = ~2s
        render_reconnect(reason, attempt, step);
        char ch = 0;
        int key = tui_read_key_timeout(&ch, 200);
        if (key == TUI_KEY_CTRL_C || key == TUI_KEY_EOF) quit = 1;
        else if (key == TUI_KEY_CHAR && (ch == 'q' || ch == 'Q')) quit = 1;
    }
    tui_raw_disable();
    return quit ? 1 : 0;
}

int main(int argc, char *argv[]) {
    char username[64] = {0};
    char password[64] = {0};
    char room[64] = "general";
    char saved_user[64] = {0};
    char saved_room[64] = {0};

    // Load the client's own local data (independent from server storage)
    client_profile_t profile;
    if (client_profile_load(&profile) == 0) {
        if (profile.username[0]) {
            snprintf(saved_user, sizeof(saved_user), "%s", profile.username);
            snprintf(username, sizeof(username), "%s", profile.username);
        }
        if (profile.room[0]) {
            snprintf(saved_room, sizeof(saved_room), "%s", profile.room);
            snprintf(room, sizeof(room), "%s", profile.room);
        }
        printf("Loaded local profile: user='%s' room='%s'\n", saved_user, saved_room);
    }

    int have_args = (argc >= 3);
    if (have_args) {
        snprintf(username, sizeof(username), "%s", argv[1]);
        snprintf(password, sizeof(password), "%s", argv[2]);
        if (argc >= 4) snprintf(room, sizeof(room), "%s", argv[3]);
    }

    tui_init();

#ifdef _WIN32
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    int logged_in_ever = 0;   // have we authenticated at least once?
    int app_exit = 0;
    int attempt = 0;

    while (!app_exit) {
        // ---- connect ----
        int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(SERVER_PORT);
        inet_pton(AF_INET, SERVER_HOST, &addr.sin_addr);

        if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            CLOSE_SOCKET(fd);
            if (reconnect_wait("Cannot connect to server", ++attempt)) { app_exit = 1; }
            continue;
        }
        if (do_handshake(fd, SERVER_HOST, SERVER_PORT) < 0) {
            CLOSE_SOCKET(fd);
            if (reconnect_wait("WebSocket handshake failed", ++attempt)) { app_exit = 1; }
            continue;
        }

        // ---- authenticate ----
        if (!logged_in_ever) {
            int logged_in;
            if (have_args) {
                logged_in = (do_login(fd, username, password) == 0);
            } else {
                logged_in = auth_flow(fd, username, sizeof(username),
                                      password, sizeof(password));
            }
            if (!logged_in) {
                printf("Not logged in. Exiting.\n");
                CLOSE_SOCKET(fd);
                break;
            }
            logged_in_ever = 1;
        } else {
            // Reconnect: log back in with the stored credentials.
            if (do_login(fd, username, password) != 0) {
                CLOSE_SOCKET(fd);
                if (reconnect_wait("Re-login failed", ++attempt)) { app_exit = 1; }
                continue;
            }
        }

        attempt = 0;
        snprintf(g_nickname, sizeof(g_nickname), "%s", username);

        // ---- start receive thread ----
        g_fd = fd;
        g_recv_running = 1;
        g_disconnected = 0;
        g_hb_stop = 0;
        pthread_t recv_tid, hb_tid;
        pthread_create(&recv_tid, NULL, recv_loop, NULL);
        pthread_create(&hb_tid, NULL, heartbeat_loop, NULL);

        int direct = have_args;
        int exit_all = 0;

        while (!exit_all && !g_disconnected) {
            chat_reset_view();

            if (direct) {
                const char *code = (argc >= 5) ? argv[4] : "";
                char join[MAX_MSG_LEN];
                snprintf(join, sizeof(join),
                         "{\"type\":\"JOIN\",\"room\":\"%s\",\"code\":\"%s\"}", room, code);
                ws_send_json(fd, join);
                char jresp[8192];
                await_response(jresp, sizeof(jresp));
                display_message(jresp);
                char type[32] = {0};
                json_get_string(jresp, "type", type, sizeof(type));
                if (strcmp(type, "JOINED") != 0) {
                    printf("Join failed.\n");
                    exit_all = 1;
                    break;
                }
                direct = 0;
            } else {
                int sr = select_room(fd, room, sizeof(room));
                if (sr == 1) { exit_all = 1; break; }   // user quit
                if (sr != 0) break;                     // disconnected/error
            }

            // Room name is authoritative from the JOINED response
            pthread_mutex_lock(&g_chat_lock);
            snprintf(room, sizeof(room), "%s", g_chat.room);
            pthread_mutex_unlock(&g_chat_lock);

            // Persist this client's profile locally
            {
                client_profile_t out;
                memset(&out, 0, sizeof(out));
                snprintf(out.username, sizeof(out.username), "%s", username);
                snprintf(out.room, sizeof(out.room), "%s", room);
                client_profile_save(&out);
            }

            g_chat.mode = 1;
            g_chat.msg_scroll = 0;
            int cr = chat_run();
            g_chat.mode = 0;

            if (cr == CHAT_RESULT_EXIT) { exit_all = 1; }
            else if (cr == CHAT_RESULT_DISCONN) { break; }
            else if (cr == CHAT_RESULT_LOGOUT) { g_logged_out = 1; break; }
        }

        // ---- tear down this connection ----
        g_recv_running = 0;
        g_hb_stop = 1;                       // stop the keepalive thread first
        pthread_join(hb_tid, NULL);          // it exits within ~1s
        uint8_t close_buf[16];
        int clen = ws_frame_encode(WS_OPCODE_CLOSE, NULL, 0, true, close_buf, sizeof(close_buf));
        if (clen > 0) send(fd, (char *)close_buf, clen, 0);
        CLOSE_SOCKET(fd);
        pthread_join(recv_tid, NULL);

        if (exit_all) { app_exit = 1; break; }

        if (g_logged_out) {
            // User logged out: reconnect and show the auth screen again.
            g_logged_out = 0;
            logged_in_ever = 0;
            printf("Logged out.\n");
            SLEEP_MS(200);
            continue;
        }

        if (g_disconnected) {
            if (reconnect_wait("Server connection lost", ++attempt)) { app_exit = 1; }
            continue;
        }
        break;   // some other error: stop
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

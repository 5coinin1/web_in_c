#include "common.h"
#include "connection.h"
#include "room.h"
#include "auth.h"
#include "path_util.h"
#include "tui.h"
#include <signal.h>
#include <pthread.h>
#include <time.h>

static volatile int g_running = 1;
static volatile int g_server_fd = -1;
static volatile int g_client_count = 0;
static client_t *g_clients = NULL;
static pthread_mutex_t g_clients_lock = PTHREAD_MUTEX_INITIALIZER;

static void signal_handler(int sig) {
    (void)sig;
    g_running = 0;
}

// On shutdown, do NOT free clients here: each client is owned by its own
// thread, which is still running (parked in recv()). Freeing it from this
// thread would be a double-free / use-after-free, because the client thread
// also destroys its client when it exits. Instead, just wake every reader by
// shutting its socket down; each thread then tears down its own client through
// the normal path. main() waits for the count to reach 0.
static void shutdown_all_clients(void) {
    pthread_mutex_lock(&g_clients_lock);
    for (client_t *c = g_clients; c; c = c->next) {
        SHUTDOWN_BOTH(c->fd);
    }
    pthread_mutex_unlock(&g_clients_lock);
}

static void add_client(client_t *client) {
    pthread_mutex_lock(&g_clients_lock);
    client->next = g_clients;
    g_clients = client;
    g_client_count++;
    pthread_mutex_unlock(&g_clients_lock);
}

static void remove_client_from_list(client_t *client) {
    pthread_mutex_lock(&g_clients_lock);
    if (g_clients == client) {
        g_clients = client->next;
    } else {
        client_t *prev = g_clients;
        while (prev && prev->next != client) prev = prev->next;
        if (prev) prev->next = client->next;
    }
    if (g_client_count > 0) g_client_count--;
    pthread_mutex_unlock(&g_clients_lock);
}

static void *client_thread(void *arg) {
    client_t *client = (client_t *)arg;
    char recv_buf[4096];

    LOG_INFO("Client thread started for fd=%d", client->fd);

    while (g_running) {
        int n = recv(client->fd, recv_buf, sizeof(recv_buf), 0);
        if (n <= 0) {
            if (n == 0) {
                LOG_INFO("Client fd=%d disconnected", client->fd);
            } else {
                LOG_ERR("recv failed for fd=%d: %d", client->fd, GET_ERR());
            }
            break;
        }
        client->last_active = time(NULL);

        // Append to client's read buffer
        int space = (int)sizeof(client->read_buf) - client->read_len;
        if (n > space) {
            LOG_ERR("Client fd=%d buffer overflow", client->fd);
            break;
        }
        memcpy(client->read_buf + client->read_len, recv_buf, n);
        client->read_len += n;
        client->read_buf[client->read_len] = '\0';

        int r = client_process_buffer(client);
        if (r < 0) {
            LOG_INFO("Client fd=%d processing error, closing", client->fd);
            break;
        }
    }

    // Cleanup
    int fd = client->fd;
    remove_client_from_list(client);
    client_destroy(client);
    LOG_INFO("Client thread fd=%d exiting", fd);
    return NULL;
}

static void console_help(void) {
    CONSOLE("Commands:");
    CONSOLE("  room <name> <code|-> <description...>   create a room (- = no code)");
    CONSOLE("  del <name>                              delete a room");
    CONSOLE("  list                                    list rooms");
    CONSOLE("  help                                    show this help");
    CONSOLE("  quit                                    stop the server");
}

static void console_quit(void) {
    g_running = 0;   // the accept loop polls this and exits on its own
}

static void run_command(const char *line_in) {
    char line[512];
    snprintf(line, sizeof(line), "%s", line_in);

    char cmd[32] = {0};
    sscanf(line, "%31s", cmd);
    const char *rest = line + strlen(cmd);
    while (*rest == ' ') rest++;

    if (strcmp(cmd, "quit") == 0 || strcmp(cmd, "exit") == 0) {
        console_quit();
    } else if (strcmp(cmd, "help") == 0) {
        console_help();
    } else if (strcmp(cmd, "list") == 0 || strcmp(cmd, "rooms") == 0) {
        room_print_console();
    } else if (strcmp(cmd, "room") == 0) {
        char name[64] = {0}, code[64] = {0}, desc[320] = {0};
        int consumed = 0;
        if (sscanf(rest, "%63s %63s%n", name, code, &consumed) >= 2) {
            const char *d = rest + consumed;
            while (*d == ' ') d++;
            snprintf(desc, sizeof(desc), "%s", d);
            if (strcmp(code, "-") == 0) code[0] = '\0';
            int r = room_create(name, desc, code);
            if (r == ROOM_CREATE_OK)          CONSOLE("Room '%s' created.", name);
            else if (r == ROOM_CREATE_EXISTS) CONSOLE("Room '%s' already exists.", name);
            else                              CONSOLE("Invalid room name '%s'.", name);
        } else {
            CONSOLE("Usage: room <name> <code|-> <description...>");
        }
    } else if (strcmp(cmd, "del") == 0 || strcmp(cmd, "delete") == 0) {
        char name[64] = {0};
        if (sscanf(rest, "%63s", name) == 1) {
            int r = room_delete(name);
            if (r == ROOM_DELETE_OK) CONSOLE("Room '%s' deleted.", name);
            else                     CONSOLE("Room '%s' not found.", name);
        } else {
            CONSOLE("Usage: del <name>");
        }
    } else {
        CONSOLE("Unknown command '%s'. Type 'help'.", cmd);
    }
}

// ---- console TUI rendering ----
static pthread_mutex_t g_console_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_cinput[512];
static int  g_cinput_len = 0;
static int  g_log_scroll = 0;
static volatile int g_console_dirty = 1;   // needs redraw
static char g_cframe[1 << 16];
static int  g_cframe_len;

static void cfb_puts(const char *s) {
    int n = (int)strlen(s);
    if (g_cframe_len + n < (int)sizeof(g_cframe) - 1) {
        memcpy(g_cframe + g_cframe_len, s, n);
        g_cframe_len += n;
    }
}
static void cfb_printf(const char *fmt, ...) {
    char tmp[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    cfb_puts(tmp);
}

static void render_console(void) {
    if (!tui_is_tty()) return;

    int cols, rows;
    tui_size(&cols, &rows);
    if (cols < 50) cols = 50;
    if (rows < 8) rows = 8;

    pthread_mutex_lock(&g_console_lock);

    int total = log_total();
    int body_top = 3;
    int body_h = (rows - 2) - body_top + 1;
    if (body_h < 1) body_h = 1;

    int bottom_idx = total - 1 - g_log_scroll;
    int top_idx = bottom_idx - (body_h - 1);
    if (top_idx < 0) top_idx = 0;

    int nclients = g_client_count;
    int nrooms = room_count();

    g_cframe_len = 0;
    cfb_puts("\033[H");

    // Row 1: status header
    char head[256];
    snprintf(head, sizeof(head),
             " WebSocket Chat Server   port %d   clients: %d   rooms: %d",
             SERVER_PORT, nclients, nrooms);
    char hc[256];
    snprintf(hc, sizeof(hc), "%.*s", cols, head);
    cfb_printf("\033[1;1H\033[2K");
    cfb_puts(TUI_GREEN TUI_BOLD);
    cfb_puts(hc);
    cfb_puts(TUI_RESET);

    // Row 2: separator
    cfb_printf("\033[2;1H\033[2K");
    cfb_puts(TUI_BLUE);
    for (int i = 0; i < cols; i++) cfb_puts("-");
    cfb_puts(TUI_RESET);

    // Body: log lines
    for (int r = 0; r < body_h; r++) {
        cfb_printf("\033[%d;1H\033[2K", body_top + r);
        int li = top_idx + r;
        if (li >= 0 && li < total) {
            const char *lt = log_line_at(li);
            int lv = log_level_at(li);
            const char *color = (lv == 1) ? TUI_RED : (lv == 2 ? TUI_YELLOW : TUI_DIM);
            char tmp[256];
            snprintf(tmp, sizeof(tmp), "%.*s", cols, lt);
            cfb_puts(color);
            cfb_puts(tmp);
            cfb_puts(TUI_RESET);
        }
    }

    // Bottom row -1: command hint footer
    const char *hint =
        " room <name> <code|-> <desc> | del <name> | list | help | quit";
    char hb[256];
    {
        int first = top_idx + 1;
        int last = top_idx + body_h;
        if (last > total) last = total;
        if (first < 1) first = 1;
        snprintf(hb, sizeof(hb), " [lines %d-%d of %d]%s  |%s",
                 first, last, total,
                 g_log_scroll > 0 ? "  <SCROLLED, PgDn=bottom>" : "", hint);
    }
    cfb_printf("\033[%d;1H\033[2K", rows - 1);
    cfb_puts(TUI_CYAN);
    char hc2[256];
    snprintf(hc2, sizeof(hc2), "%.*s", cols, hb);
    cfb_puts(hc2);
    cfb_puts(TUI_RESET);

    // Bottom row: input line
    cfb_printf("\033[%d;1H\033[2K", rows);
    cfb_puts(TUI_BOLD "> " TUI_RESET);
    cfb_puts(g_cinput);
    cfb_printf("\033[%d;%dH", rows, 3 + g_cinput_len);

    fwrite(g_cframe, 1, g_cframe_len, stdout);
    fflush(stdout);

    pthread_mutex_unlock(&g_console_lock);
}

// Log sink: do NOT redraw here (log_emit can fire many times per second).
// Just mark the console dirty; the console thread redraws on its own tick.
static void console_sink(void) {
    g_console_dirty = 1;
}

// Interactive admin console. TUI when stdout is a terminal, plain otherwise.
static void *console_thread(void *arg) {
    (void)arg;

    if (tui_is_tty()) {
        tui_init();
        log_set_sink(console_sink);
        tui_clear();
        tui_raw_enable();

        for (;;) {
            if (g_console_dirty) {
                render_console();
                g_console_dirty = 0;
            }

            char ch = 0;
            int key = tui_read_key_timeout(&ch, 100);
            if (key == TUI_KEY_NONE) continue;   // timeout: loop re-checks dirty

            int cols, rows;
            tui_size(&cols, &rows);
            g_console_dirty = 1;   // any handled key redraws

            if (key == TUI_KEY_CTRL_C || key == TUI_KEY_EOF) {
                console_quit();
                break;
            }
            if (key == TUI_KEY_ENTER) {
                char line[512];
                pthread_mutex_lock(&g_console_lock);
                snprintf(line, sizeof(line), "%s", g_cinput);
                g_cinput_len = 0;
                g_cinput[0] = '\0';
                pthread_mutex_unlock(&g_console_lock);
                run_command(line);
                continue;
            }
            if (key == TUI_KEY_BACKSPACE) {
                pthread_mutex_lock(&g_console_lock);
                if (g_cinput_len > 0) g_cinput[--g_cinput_len] = '\0';
                pthread_mutex_unlock(&g_console_lock);
                continue;
            }
            if (key == TUI_KEY_PGUP || key == TUI_KEY_UP || key == TUI_KEY_WHEEL_UP) {
                pthread_mutex_lock(&g_console_lock);
                int body_h = (rows - 2) - 3 + 1;
                if (body_h < 1) body_h = 1;
                int total = log_total();
                int maxscroll = total > body_h ? total - body_h : 0;
                int step = (key == TUI_KEY_PGUP) ? (rows > 4 ? rows - 4 : 5)
                         : (key == TUI_KEY_WHEEL_UP) ? 3 : 1;
                g_log_scroll += step;
                if (g_log_scroll > maxscroll) g_log_scroll = maxscroll;
                pthread_mutex_unlock(&g_console_lock);
                continue;
            }
            if (key == TUI_KEY_PGDN || key == TUI_KEY_DOWN || key == TUI_KEY_WHEEL_DOWN) {
                pthread_mutex_lock(&g_console_lock);
                int step = (key == TUI_KEY_PGDN) ? (rows > 4 ? rows - 4 : 5)
                         : (key == TUI_KEY_WHEEL_DOWN) ? 3 : 1;
                g_log_scroll -= step;
                if (g_log_scroll < 0) g_log_scroll = 0;
                pthread_mutex_unlock(&g_console_lock);
                continue;
            }
            if (key == TUI_KEY_CHAR) {
                if (ch >= 32) {
                    pthread_mutex_lock(&g_console_lock);
                    if (g_cinput_len < (int)sizeof(g_cinput) - 1) {
                        g_cinput[g_cinput_len++] = ch;
                        g_cinput[g_cinput_len] = '\0';
                    }
                    pthread_mutex_unlock(&g_console_lock);
                }
                continue;
            }
            // Ignore anything else (left/right arrows, function keys, ...).
        }
        tui_raw_disable();
    } else {
        // Plain fallback (piped input / non-console)
        char line[512];
        console_help();
        while (g_running && fgets(line, sizeof(line), stdin)) {
            line[strcspn(line, "\r\n")] = '\0';
            if (line[0] != '\0') run_command(line);
        }
    }
    return NULL;
}

// Periodically close connections that have been idle for too long. Closing the
// socket (shutdown) makes the client thread's recv() return so it can clean up
// and release the account session.
static void *idle_janitor(void *arg) {
    (void)arg;
    while (g_running) {
#ifdef _WIN32
        Sleep(5000);
#else
        sleep(5);
#endif
        time_t now = time(NULL);
        pthread_mutex_lock(&g_clients_lock);
        for (client_t *c = g_clients; c; c = c->next) {
            if (now - c->last_active > IDLE_TIMEOUT_SECS) {
                LOG_INFO("Idle timeout: closing fd=%d", c->fd);
                SHUTDOWN_BOTH(c->fd);
            }
        }
        pthread_mutex_unlock(&g_clients_lock);
    }
    return NULL;
}

// If running in a terminal, keep the window open so startup errors are visible
// (e.g. when launched by double-click).
static void fatal_pause(void) {    if (!tui_is_tty()) return;
    printf("\nPress Enter to exit...");
    fflush(stdout);
    char b[8];
    if (!fgets(b, sizeof(b), stdin)) { /* ignore */ }
}

int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;

    // Unbuffered stdout so logs appear immediately (important when piped)
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Signal handling
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#ifdef _WIN32
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        LOG_ERR("WSAStartup failed");
        return 1;
    }
#endif

    // Server data lives next to the project root, independent of the CWD.
    char server_data_dir[1024];
    data_dir_path(SERVER_DATA_DIR, server_data_dir, sizeof(server_data_dir));

    room_init(server_data_dir);
    auth_init(server_data_dir);

    // Create TCP socket
    int server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_fd < 0) {
        LOG_ERR("socket() failed: %d", GET_ERR());
        return 1;
    }

    // Allow port reuse (POSIX) / exclusive binding (Windows)
#ifdef _WIN32
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *)&opt, sizeof(opt));
#else
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
#endif

    // Bind
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(SERVER_PORT);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERR("bind() failed: %d - is another wschat_server already using port %d?",
                GET_ERR(), SERVER_PORT);
        CLOSE_SOCKET(server_fd);
        fatal_pause();
        return 1;
    }

    // Listen
    if (listen(server_fd, 16) < 0) {
        LOG_ERR("listen() failed: %d", GET_ERR());
        CLOSE_SOCKET(server_fd);
        fatal_pause();
        return 1;
    }

    g_server_fd = server_fd;

    LOG_INFO("WebSocket Chat Server listening on port %d", SERVER_PORT);
    LOG_INFO("Type 'help' in this console for admin commands, or Ctrl+C to stop");

    // Admin console on its own thread
    pthread_t console_tid;
    if (pthread_create(&console_tid, NULL, console_thread, NULL) == 0) {
        pthread_detach(console_tid);
    }

    // Idle-connection janitor
    pthread_t janitor_tid;
    if (pthread_create(&janitor_tid, NULL, idle_janitor, NULL) == 0) {
        pthread_detach(janitor_tid);
    }

    // Accept loop. Uses select() with a short timeout so the loop notices
    // g_running becoming 0 (from 'quit' or a signal) and shuts down cleanly.
    while (g_running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(server_fd, &rfds);
        struct timeval tv;
        tv.tv_sec = 0;
        tv.tv_usec = 200000;   // 200 ms

        int sel = select((int)server_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (g_running) LOG_ERR("select() failed: %d", GET_ERR());
            continue;
        }
        if (sel == 0) continue;   // timeout: re-check g_running

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (g_running) LOG_ERR("accept() failed: %d", GET_ERR());
            continue;
        }

        LOG_INFO("New connection from %s:%d (fd=%d)",
                 inet_ntoa(client_addr.sin_addr),
                 ntohs(client_addr.sin_port),
                 client_fd);

        // Bound blocking sends so a stalled peer cannot pin a writer thread.
        socket_set_send_timeout(client_fd, CLIENT_SEND_TIMEOUT_SECS);
        socket_set_sndbuf(client_fd, CLIENT_SNDBUF);

        client_t *client = client_create(client_fd);
        if (!client) {
            LOG_ERR("Failed to create client for fd=%d", client_fd);
            CLOSE_SOCKET(client_fd);
            continue;
        }

        // Writer thread owns send(); the reader thread below owns recv().
        if (client_start_writer(client) != 0) {
            LOG_ERR("Failed to create writer thread for fd=%d", client_fd);
            client_destroy(client);
            continue;
        }

        add_client(client);

        pthread_t tid;
        if (pthread_create(&tid, NULL, client_thread, client) != 0) {
            LOG_ERR("Failed to create thread for fd=%d", client_fd);
            remove_client_from_list(client);
            client_destroy(client);
            continue;
        }
        pthread_detach(tid);
    }

    LOG_INFO("Server shutting down...");
    // Wake every client thread; each frees its own client. Wait (bounded) for
    // them to finish so no thread is still touching a client after main exits.
    shutdown_all_clients();
    for (int i = 0; i < 50 && g_client_count > 0; i++) {
#ifdef _WIN32
        Sleep(100);
#else
        usleep(100 * 1000);
#endif
    }
    if (g_server_fd >= 0) { CLOSE_SOCKET(g_server_fd); g_server_fd = -1; }

#ifdef _WIN32
    WSACleanup();
#endif

    return 0;
}

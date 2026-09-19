#ifndef COMMON_H
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    typedef int socklen_t;
    #define CLOSE_SOCKET(s) closesocket(s)
    #define GET_ERR() WSAGetLastError()
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>
    #define CLOSE_SOCKET(s) close(s)
    #define GET_ERR() errno
#endif

#define SERVER_PORT 9090
#define MAX_ROOM_NAME 32
#define MAX_NICKNAME 32
#define MAX_MSG_LEN 4096
#define MAX_CLIENTS_PER_ROOM 32
#define WS_FRAME_MAX_PAYLOAD (1 << 20) // 1MB

void log_emit(int level, const char *file, int line, const char *fmt, ...);

#define LOG_INFO(fmt, ...) log_emit(0, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...)  log_emit(1, __FILE__, __LINE__, fmt, ##__VA_ARGS__)
#define CONSOLE(fmt, ...)  log_emit(2, NULL, 0, fmt, ##__VA_ARGS__)

// ---- log ring buffer (used by the server console UI) ----
#define LOG_RING_SIZE 512
int         log_total(void);              // number of lines emitted so far
const char *log_line_at(int index);       // line text for absolute index
int         log_level_at(int index);      // 0 = info, 1 = error

typedef void (*log_sink_fn)(void);
void log_set_sink(log_sink_fn fn);        // called after each new line (if set)

// WebSocket opcodes (RFC 6455 Section 5.2)
#define WS_OPCODE_TEXT  0x1
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING  0x9
#define WS_OPCODE_PONG  0xA

// Client states
typedef enum {
    STATE_HTTP_HANDSHAKE,   // TCP connected, reading HTTP upgrade request
    STATE_WS_CONNECTED,     // WebSocket open, not yet authenticated
    STATE_AUTHENTICATED,    // logged in, not yet in a room
    STATE_IN_ROOM           // joined a chat room
} client_state_t;

#endif

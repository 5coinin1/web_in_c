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
    #define SHUTDOWN_BOTH(s) shutdown(s, SD_BOTH)
    #define GET_ERR() WSAGetLastError()
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <errno.h>
    #define CLOSE_SOCKET(s) close(s)
    #define SHUTDOWN_BOTH(s) shutdown(s, SHUT_RDWR)
    #define GET_ERR() errno
#endif

#define SERVER_PORT 9090
#define IDLE_TIMEOUT_SECS 90
#define MAX_ROOM_NAME 32
#define MAX_NICKNAME 32
#define MAX_MSG_LEN 4096
#define MAX_CLIENTS_PER_ROOM 32
#define WS_FRAME_MAX_PAYLOAD (1 << 20) // 1MB

// ---- per-client outbound queue (producer/consumer, PA2) ----
//
// room_broadcast() must never touch the network while holding room_lock: one
// peer that stops reading would otherwise block send() and freeze every room.
// Instead the producer only copies the encoded frame into this ring buffer and
// signals the client's writer thread, which owns send() and runs outside all
// room locks. A client whose backlog exceeds CLIENT_OUT_QUEUE is considered
// too slow and is disconnected, so the queue can never grow without bound.
#define CLIENT_OUT_QUEUE         (256 * 1024)
#define CLIENT_SEND_TIMEOUT_SECS 1
#define CLIENT_SNDBUF            (64 * 1024)

// Cap the kernel send buffer per connection. Without this the OS may
// auto-tune it very large, so a stalled peer only trips the app-level
// CLIENT_OUT_QUEUE limit after megabytes of buffering. Bounding it makes the
// slow-consumer decision prompt and the memory footprint predictable.
static inline void socket_set_sndbuf(int fd, int bytes) {
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (const char *)&bytes, sizeof(bytes));
}

// Bound how long a blocking send() may wait, so a writer thread always gets
// back to its loop and can observe a shutdown request.
static inline void socket_set_send_timeout(int fd, int secs) {
#ifdef _WIN32
    int ms = secs * 1000;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&ms, sizeof(ms));
#else
    struct timeval tv;
    tv.tv_sec = secs;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

// True when send() failed only because the peer/socket is momentarily full.
static inline int socket_send_would_block(void) {
#ifdef _WIN32
    int e = WSAGetLastError();
    return e == WSAEWOULDBLOCK || e == WSAETIMEDOUT;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR;
#endif
}

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
    STATE_IDLE,             // accepted, before any bytes are read
    STATE_HTTP_HANDSHAKE,   // reading the HTTP upgrade request
    STATE_WS_CONNECTED,     // WebSocket open, not yet authenticated
    STATE_AUTHENTICATED,    // logged in, not yet in a room
    STATE_IN_ROOM,          // joined a chat room
    STATE_CLOSED            // terminal: connection gone
} client_state_t;

#endif

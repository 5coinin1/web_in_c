#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"
#include "ws_frame.h"
#include <time.h>
#include <pthread.h>

typedef struct client {
    int           fd;
    client_state_t state;
    char          nickname[MAX_NICKNAME];
    char          room[MAX_ROOM_NAME];
    char          read_buf[MAX_MSG_LEN * 2]; // buffered incoming data
    int           read_len;
    volatile time_t last_active;             // for idle timeout
    struct client *next;  // next client in the server's client list

    // ---- outbound queue (see CLIENT_OUT_QUEUE in common.h) ----
    pthread_mutex_t out_mu;          // guards the ring buffer and the flags
    pthread_cond_t  out_cv;          // producer signals the writer
    uint8_t        *out_buf;         // CLIENT_OUT_QUEUE bytes, allocated once
    size_t          out_head;        // ring read position
    size_t          out_len;         // bytes currently queued
    int             out_stop;        // writer must exit (client going away)
    int             out_kick;        // overflow or fatal send error: disconnect
    pthread_t       writer_tid;
    int             writer_started;
} client_t;

// Create a new client (malloc + init)
client_t *client_create(int fd);

// Start the per-client writer thread that owns send(). Returns 0 on success.
int client_start_writer(client_t *client);

// Free client resources
void client_destroy(client_t *client);

// Process any complete request/frames buffered for this client.
// Returns 0 to keep the connection open, -1 to close it.
int client_process_buffer(client_t *client);

// Queue a WebSocket text frame for asynchronous delivery.
int client_send_ws_text(client_t *client, const char *text);

// Queue a close frame.
int client_send_close(client_t *client);

#endif

#ifndef CLIENT_H
#define CLIENT_H

#include "common.h"
#include "ws_frame.h"

typedef struct client {
    int           fd;
    client_state_t state;
    char          nickname[MAX_NICKNAME];
    char          room[MAX_ROOM_NAME];
    char          read_buf[MAX_MSG_LEN * 2]; // buffered incoming data
    int           read_len;
    struct client *next;  // next client in the server's client list
} client_t;

// Create a new client (malloc + init)
client_t *client_create(int fd);

// Free client resources
void client_destroy(client_t *client);

// Process any complete request/frames buffered for this client.
// Returns 0 to keep the connection open, -1 to close it.
int client_process_buffer(client_t *client);

// Send a raw WebSocket frame (text)
int client_send_ws_text(client_t *client, const char *text);

// Send a close frame
int client_send_close(client_t *client);

#endif

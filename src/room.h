#ifndef ROOM_H
#define ROOM_H

#include "common.h"

struct client; // forward declaration

typedef struct room {
    char           name[MAX_ROOM_NAME];
    char           description[160];
    char           code[16];        // empty => no code required
    struct client *clients[MAX_CLIENTS_PER_ROOM];
    int            num_clients;
    struct room   *next;
} room_t;

// Result codes for room_join and room_join_commit
#define ROOM_JOIN_OK        0
#define ROOM_JOIN_NOTFOUND -1
#define ROOM_JOIN_BADCODE  -2
#define ROOM_JOIN_FULL     -3
#define ROOM_JOIN_BADSTATE -4   // caller is not STATE_AUTHENTICATED

// Result codes for room_create
#define ROOM_CREATE_OK        0
#define ROOM_CREATE_EXISTS   -1
#define ROOM_CREATE_INVALID  -2

// Result codes for room_delete
#define ROOM_DELETE_OK        0
#define ROOM_DELETE_NOTFOUND -1

// Load persisted rooms from <data_dir>/rooms.dat (creates the directory).
// Does NOT seed any rooms: rooms are provisioned at runtime.
void room_init(const char *data_dir);

// Create a room and persist it. Returns a ROOM_CREATE_* code.
int room_create(const char *name, const char *description, const char *code);

// Delete a room and persist the change. Returns a ROOM_DELETE_* code.
int room_delete(const char *name);

// Atomic join: validate the caller state, room, code and capacity, append the
// member, set client->room and apply CLIENT_EVENT_JOIN_OK - all under a single
// room_lock hold.
//
// room_delete() also takes room_lock, so it can never interleave with a
// half-finished join. This is what keeps the invariant
//     (client is in room->clients[])  <->  (state == STATE_IN_ROOM)
// inductive: unlike the earlier "join, then re-check" sequence, there is no
// window in which membership and state disagree, and no compensating rollback
// is needed. Returns ROOM_JOIN_*.
int room_join_commit(const char *room_name, const char *nickname,
                     struct client *client, const char *code);

// Leave a room. Returns 0 on success.
int room_leave(const char *room_name, const char *nickname);

// Broadcast message to all clients in room. If exclude_nick is NULL, send to all.
void room_broadcast(const char *room_name, const char *exclude_nick,
                    const char *msg, int exclude_fd);

// Get JSON list of users in room. Writes into out_buf.
void room_get_users(const char *room_name, char *out_buf, size_t out_buf_size);

// Write a ready-to-send ROOM_LIST JSON message into out_buf.
void room_list_json(char *out_buf, size_t out_buf_size);

// Print a human-readable room table to stdout (for the server console).
void room_print_console(void);

// Number of rooms currently defined.
int room_count(void);

#endif

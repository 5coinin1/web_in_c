#ifndef ROOM_H
#define ROOM_H

#include "common.h"
#include <pthread.h>

struct client; // forward declaration

typedef struct room {
    char           name[MAX_ROOM_NAME];
    char           description[160];
    char           code[16];        // empty => no code required
    struct client *clients[MAX_CLIENTS_PER_ROOM];
    int            num_clients;
    struct room   *next;

    // Per-room lock: guards clients[] and num_clients for THIS room only, so
    // operations on different rooms proceed in parallel. The module's list
    // lock (see room.c) guards the room list and the fields below.
    pthread_mutex_t lock;
    int             refs;           // active users of this room (list lock)
    int             deleting;       // set while room_delete() tears it down
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
// room-lock hold.
//
// room_delete() takes the same room lock, so it can never interleave with a
// half-finished join. This is what keeps the invariant
//     (client is in room->clients[])  <->  (state == STATE_IN_ROOM)
// inductive: unlike the earlier "join, then re-check" sequence, there is no
// window in which membership and state disagree, and no compensating rollback
// is needed. Returns ROOM_JOIN_*.
int room_join_commit(const char *room_name, struct client *client,
                     const char *code);

// Leave a room. Members are identified by the client pointer, so removal can
// never miss (the old nickname-keyed lookup silently left a dangling pointer
// in room->clients[] when the caller passed a nickname other than
// client->nickname). Returns 0 on success.
int room_leave(const char *room_name, struct client *client);

// Broadcast a message to every member of a room. `exclude` (may be NULL) is the
// sending client, excluded by pointer identity.
void room_broadcast(const char *room_name, struct client *exclude,
                    const char *msg);

// Get JSON list of users in room. Writes into out_buf.
void room_get_users(const char *room_name, char *out_buf, size_t out_buf_size);

// Write one page of the room list as a ROOM_LIST message. Emits up to `limit`
// rooms starting at `offset` (and no more than fits in out_buf). Sets
// *has_more when rooms remain beyond this page, so the client can page.
void room_list_page_json(char *out_buf, size_t out_buf_size, int offset,
                         int limit, int *has_more);

// Print a human-readable room table to stdout (for the server console).
void room_print_console(void);

// Number of rooms currently defined.
int room_count(void);

#endif

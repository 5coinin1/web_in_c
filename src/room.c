#include "room.h"
#include "connection.h"
#include "state_machine.h"
#include "bytes.h"
#include "path_util.h"
#include "json_util.h"
#include <ctype.h>
#include <pthread.h>

#define ROOM_DESC_LEN 160
#define ROOM_CODE_LEN 16
#define RECORD_SIZE   (MAX_ROOM_NAME + ROOM_DESC_LEN + ROOM_CODE_LEN)  // 32+160+16 = 208
#define ROOM_MAGIC    "WSRM"
#define ROOM_VERSION  1

static room_t *room_list = NULL;
// Guards the room list and each room's refs/deleting. Operations on a specific
// room additionally take that room's own lock, so unrelated rooms don't block
// each other. Lock order is always: list_lock -> room->lock.
static pthread_mutex_t list_lock = PTHREAD_MUTEX_INITIALIZER;
static char g_rooms_path[256] = "server_data/rooms.dat";
static volatile int g_room_count = 0;   // lock-free count for the console UI

static bool valid_room_name(const char *name) {
    size_t len = strlen(name);
    if (len < 1 || len >= MAX_ROOM_NAME) return false;
    for (size_t i = 0; i < len; i++) {
        if (!isalnum((unsigned char)name[i]) && name[i] != '_' && name[i] != '-')
            return false;
    }
    return true;
}

// Find a room by name. Caller must hold list_lock. No reference is taken.
static room_t *find_room(const char *name) {
    room_t *r = room_list;
    while (r) {
        if (strcmp(r->name, name) == 0) return r;
        r = r->next;
    }
    return NULL;
}

// Find a room and take a reference to it. Caller must hold list_lock. Returns
// NULL if not found. Pair with room_unref() once the room lock is released.
static room_t *find_room_ref(const char *name) {
    room_t *r = find_room(name);
    if (r) r->refs++;
    return r;
}

// Drop a reference. If this was the last user of a room that room_delete()
// already unlinked, free it here (the deleter could not free it while in use).
static void room_unref(room_t *r) {
    pthread_mutex_lock(&list_lock);
    int free_it = (--r->refs == 0 && r->deleting);
    pthread_mutex_unlock(&list_lock);
    if (free_it) {
        pthread_mutex_destroy(&r->lock);
        free(r);
    }
}

// ---- persistence ----
static void room_save_locked(void) {
    char tmp[300];
    FILE *f = atomic_open(g_rooms_path, tmp, sizeof(tmp));
    if (!f) {
        LOG_ERR("Cannot write rooms file '%s'", g_rooms_path);
        return;
    }
    uint32_t count = 0;
    for (room_t *r = room_list; r; r = r->next) count++;

    uint8_t header[12];
    memcpy(header, ROOM_MAGIC, 4);
    put_u16(header + 4, ROOM_VERSION);
    put_u16(header + 6, 0);
    put_u32(header + 8, count);
    fwrite(header, 1, sizeof(header), f);

    for (room_t *r = room_list; r; r = r->next) {
        uint8_t rec[RECORD_SIZE];
        memset(rec, 0, sizeof(rec));
        memcpy(rec, r->name, strlen(r->name));
        memcpy(rec + MAX_ROOM_NAME, r->description, strlen(r->description));
        memcpy(rec + MAX_ROOM_NAME + ROOM_DESC_LEN, r->code, strlen(r->code));
        fwrite(rec, 1, sizeof(rec), f);
    }

    if (ferror(f) != 0) { atomic_abort(tmp, f); LOG_ERR("Write error on '%s'", g_rooms_path); return; }
    if (atomic_commit(g_rooms_path, tmp, f) != 0)
        LOG_ERR("Atomic save of rooms file '%s' failed", g_rooms_path);
}

static void room_load(void) {
    FILE *f = fopen(g_rooms_path, "rb");
    if (!f) return;

    uint8_t header[12];
    if (fread(header, 1, sizeof(header), f) != sizeof(header) ||
        memcmp(header, ROOM_MAGIC, 4) != 0 || get_u16(header + 4) != ROOM_VERSION) {
        fclose(f);
        return;
    }
    uint32_t count = get_u32(header + 8);
    if (count > 4096) count = 4096;   // bound file-controlled value

    uint8_t rec[RECORD_SIZE];
    int loaded = 0;
    for (uint32_t i = 0; i < count; i++) {
        if (fread(rec, 1, sizeof(rec), f) != sizeof(rec)) break;
        room_t *r = (room_t *)calloc(1, sizeof(room_t));
        if (!r) break;
        memcpy(r->name, rec, MAX_ROOM_NAME);
        r->name[MAX_ROOM_NAME - 1] = '\0';
        memcpy(r->description, rec + MAX_ROOM_NAME, ROOM_DESC_LEN);
        r->description[ROOM_DESC_LEN - 1] = '\0';
        memcpy(r->code, rec + MAX_ROOM_NAME + ROOM_DESC_LEN, ROOM_CODE_LEN);
        r->code[ROOM_CODE_LEN - 1] = '\0';
        pthread_mutex_init(&r->lock, NULL);
        r->refs = 0;
        r->deleting = 0;
        r->next = room_list;
        room_list = r;
        loaded++;
    }
    fclose(f);
    g_room_count = loaded;
    LOG_INFO("Loaded %d room(s) from '%s'", loaded, g_rooms_path);
}

void room_init(const char *data_dir) {
    room_list = NULL;
    g_room_count = 0;
    if (data_dir && data_dir[0]) {
        snprintf(g_rooms_path, sizeof(g_rooms_path), "%s/rooms.dat", data_dir);
        ensure_dir(data_dir);
    }
    room_load();
}

int room_create(const char *name, const char *description, const char *code) {
    if (!name || !valid_room_name(name)) return ROOM_CREATE_INVALID;

    pthread_mutex_lock(&list_lock);
    if (find_room(name)) {
        pthread_mutex_unlock(&list_lock);
        return ROOM_CREATE_EXISTS;
    }

    room_t *r = (room_t *)calloc(1, sizeof(room_t));
    if (!r) {
        pthread_mutex_unlock(&list_lock);
        return ROOM_CREATE_INVALID;
    }
    pthread_mutex_init(&r->lock, NULL);
    r->refs = 0;
    r->deleting = 0;
    strncpy(r->name, name, MAX_ROOM_NAME - 1);
    strncpy(r->description, description ? description : "", ROOM_DESC_LEN - 1);
    strncpy(r->code, code ? code : "", ROOM_CODE_LEN - 1);
    r->next = room_list;
    room_list = r;
    room_save_locked();
    g_room_count++;

    pthread_mutex_unlock(&list_lock);
    LOG_INFO("Room '%s' created and persisted", name);
    return ROOM_CREATE_OK;
}

int room_delete(const char *name) {
    if (!name) return ROOM_DELETE_NOTFOUND;

    pthread_mutex_lock(&list_lock);
    room_t *prev = NULL, *r = room_list;
    while (r && strcmp(r->name, name) != 0) { prev = r; r = r->next; }
    if (!r) {
        pthread_mutex_unlock(&list_lock);
        return ROOM_DELETE_NOTFOUND;
    }

    // Evict members under the room's own lock. We hold list_lock too, so the
    // `deleting` flag is published consistently to room_unref().
    pthread_mutex_lock(&r->lock);
    r->deleting = 1;

    char notice[160];
    snprintf(notice, sizeof(notice),
             "{\"type\":\"ROOM_CLOSED\",\"room\":\"%s\"}", name);
    for (int i = 0; i < r->num_clients; i++) {
        client_t *c = r->clients[i];
        if (!c) continue;

        /* Every member in this array is STATE_IN_ROOM: room_join_commit()
         * sets membership and state together, and room_leave() removes the
         * member before changing state. The guard is a defensive invariant
         * check - ROOM_CLOSED is only legal from STATE_IN_ROOM. */
        if (c->state == STATE_IN_ROOM) {
            client_send_ws_text(c, notice);
            if (!client_state_apply(&c->state, CLIENT_EVENT_ROOM_CLOSED)) {
                LOG_ERR("Evict '%s' from room '%s': unexpected state %s",
                        c->nickname, name, client_state_name(c->state));
                c->state = STATE_AUTHENTICATED;
            }
        }
        c->room[0] = '\0';
    }
    r->num_clients = 0;
    pthread_mutex_unlock(&r->lock);

    // Unlink and persist.
    if (prev) prev->next = r->next;
    else room_list = r->next;
    room_save_locked();
    g_room_count--;

    // Free now only if no other thread holds a reference; otherwise the last
    // room_unref() frees it (see the `deleting` check there).
    int free_it = (r->refs == 0);
    pthread_mutex_unlock(&list_lock);
    if (free_it) {
        pthread_mutex_destroy(&r->lock);
        free(r);
    }

    LOG_INFO("Room '%s' deleted and persisted", name);
    return ROOM_DELETE_OK;
}

int room_leave(const char *room_name, struct client *client) {
    if (!room_name || !client) return -1;

    pthread_mutex_lock(&list_lock);
    room_t *room = find_room_ref(room_name);
    pthread_mutex_unlock(&list_lock);
    if (!room) return -1;

    pthread_mutex_lock(&room->lock);

    // Identify the member by pointer, not by nickname: a nickname-keyed lookup
    // could miss and leave a dangling pointer in the array.
    for (int i = 0; i < room->num_clients; i++) {
        if (room->clients[i] == client) {
            for (int j = i; j < room->num_clients - 1; j++) {
                room->clients[j] = room->clients[j + 1];
            }
            room->num_clients--;
            break;
        }
    }

    pthread_mutex_unlock(&room->lock);
    room_unref(room);
    return 0;
}

int room_join_commit(const char *room_name, struct client *client,
                     const char *code) {
    if (!room_name || !client) return ROOM_JOIN_NOTFOUND;

    pthread_mutex_lock(&list_lock);
    room_t *room = find_room_ref(room_name);
    pthread_mutex_unlock(&list_lock);
    if (!room) return ROOM_JOIN_NOTFOUND;

    pthread_mutex_lock(&room->lock);

    // Everything that can reject the join is checked while holding this room's
    // lock, so nothing can change between the checks, the membership update and
    // the state transition. A room being deleted (already unlinked) rejects.
    if (room->deleting) {
        pthread_mutex_unlock(&room->lock);
        room_unref(room);
        return ROOM_JOIN_NOTFOUND;
    }
    if (client->state != STATE_AUTHENTICATED) {
        pthread_mutex_unlock(&room->lock);
        room_unref(room);
        return ROOM_JOIN_BADSTATE;
    }
    if (room->code[0] != '\0') {
        if (!code || strcmp(code, room->code) != 0) {
            pthread_mutex_unlock(&room->lock);
            room_unref(room);
            return ROOM_JOIN_BADCODE;
        }
    }
    if (room->num_clients >= MAX_CLIENTS_PER_ROOM) {
        pthread_mutex_unlock(&room->lock);
        room_unref(room);
        return ROOM_JOIN_FULL;
    }

    // Commit: membership and state move together under the same lock, so no
    // observer (broadcast, delete, list) can ever see a half-joined client.
    room->clients[room->num_clients++] = client;
    snprintf(client->room, sizeof(client->room), "%s", room_name);
    if (!client_state_apply(&client->state, CLIENT_EVENT_JOIN_OK)) {
        // Unreachable: the state was checked under this same lock. Roll the
        // membership back anyway so the client is never left half-joined.
        room->num_clients--;
        client->room[0] = '\0';
        pthread_mutex_unlock(&room->lock);
        room_unref(room);
        return ROOM_JOIN_BADSTATE;
    }

    pthread_mutex_unlock(&room->lock);
    room_unref(room);
    return ROOM_JOIN_OK;
}

void room_broadcast(const char *room_name, struct client *exclude,
                    const char *msg) {
    if (!room_name || !msg) return;

    pthread_mutex_lock(&list_lock);
    room_t *room = find_room_ref(room_name);
    pthread_mutex_unlock(&list_lock);
    if (!room) return;

    pthread_mutex_lock(&room->lock);
    for (int i = 0; i < room->num_clients; i++) {
        struct client *c = room->clients[i];
        if (exclude && c == exclude) continue;
        client_send_ws_text(c, msg);
    }
    pthread_mutex_unlock(&room->lock);
    room_unref(room);
}

void room_get_users(const char *room_name, char *out_buf, size_t out_buf_size) {
    if (!room_name || !out_buf || out_buf_size < 3) return;

    pthread_mutex_lock(&list_lock);
    room_t *room = find_room_ref(room_name);
    pthread_mutex_unlock(&list_lock);
    if (!room) {
        strcpy(out_buf, "[]");
        return;
    }

    pthread_mutex_lock(&room->lock);
    out_buf[0] = '[';
    size_t pos = 1;
    for (int i = 0; i < room->num_clients; i++) {
        // Nicknames are validated (alnum/_) so they need no JSON escaping.
        char item[MAX_ROOM_NAME + 8];
        int w = snprintf(item, sizeof(item), "%s\"%s\"",
                         i > 0 ? "," : "", room->clients[i]->nickname);
        if (w <= 0) continue;
        // Keep room for the closing ']' and the NUL terminator.
        if (pos + (size_t)w + 2 > out_buf_size) break;
        memcpy(out_buf + pos, item, (size_t)w);
        pos += (size_t)w;
    }
    out_buf[pos++] = ']';
    out_buf[pos] = '\0';
    pthread_mutex_unlock(&room->lock);

    room_unref(room);
}

void room_list_page_json(char *out_buf, size_t out_buf_size, int offset,
                         int limit, int *has_more) {
    if (has_more) *has_more = 0;
    if (!out_buf || out_buf_size < 64) return;
    if (offset < 0) offset = 0;
    if (limit < 1) limit = 1;

    pthread_mutex_lock(&list_lock);

    int total = 0;
    for (room_t *r = room_list; r; r = r->next) total++;

    // Reserve room for the longest possible tail so the JSON always closes.
    const size_t tail_reserve = 80;
    size_t pos = 0;
    int n = snprintf(out_buf, out_buf_size, "{\"type\":\"ROOM_LIST\",\"rooms\":[");
    if (n > 0) pos = (size_t)n;

    int emitted = 0, index = 0;
    for (room_t *r = room_list; r; r = r->next, index++) {
        if (index < offset) continue;               // skip earlier pages
        if (emitted >= limit) break;                // page is full

        // name/desc/code are immutable while list_lock is held (no delete can
        // run); only num_clients needs the room's own lock.
        pthread_mutex_lock(&r->lock);
        int mc = r->num_clients;
        pthread_mutex_unlock(&r->lock);

        // The description is free-form admin text: escape it or a quote would
        // break the whole ROOM_LIST for every client.
        char desc[ROOM_DESC_LEN * 6 + 1];
        json_escape(r->description, desc, sizeof(desc));

        char entry[MAX_ROOM_NAME + sizeof(desc) + 128];
        int en = snprintf(entry, sizeof(entry),
            "%s{\"name\":\"%s\",\"desc\":\"%s\",\"members\":%d,\"code\":%s}",
            emitted ? "," : "", r->name, desc, mc,
            r->code[0] ? "true" : "false");
        if (en <= 0) continue;

        size_t need = (size_t)en;
        if (pos + need + tail_reserve >= out_buf_size) break;   // no room left
        memcpy(out_buf + pos, entry, need);
        pos += need;
        emitted++;
    }

    int more = (offset + emitted < total) ? 1 : 0;
    snprintf(out_buf + pos, out_buf_size - pos,
             "],\"offset\":%d,\"count\":%d,\"has_more\":%s}",
             offset, emitted, more ? "true" : "false");
    if (has_more) *has_more = more;

    pthread_mutex_unlock(&list_lock);
}

void room_print_console(void) {
    pthread_mutex_lock(&list_lock);
    log_emit(2, NULL, 0, "  %-14s %-8s %-6s %s", "ROOM", "MEMBERS", "CODE", "DESCRIPTION");
    log_emit(2, NULL, 0, "  %-14s %-8s %-6s %s", "----", "-------", "----", "-----------");
    for (room_t *r = room_list; r; r = r->next) {
        pthread_mutex_lock(&r->lock);
        int mc = r->num_clients;
        pthread_mutex_unlock(&r->lock);
        log_emit(2, NULL, 0, "  %-14s %-8d %-6s %s", r->name, mc,
                 r->code[0] ? "yes" : "-", r->description);
    }
    pthread_mutex_unlock(&list_lock);
}

int room_count(void) {
    // Lock-free: safe to call from the console renderer while list_lock is held.
    return g_room_count;
}

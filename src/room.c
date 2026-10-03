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
static pthread_mutex_t room_lock = PTHREAD_MUTEX_INITIALIZER;
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

static room_t *find_room(const char *name) {
    room_t *r = room_list;
    while (r) {
        if (strcmp(r->name, name) == 0) return r;
        r = r->next;
    }
    return NULL;
}

// ---- persistence ----
static void room_save_locked(void) {
    FILE *f = fopen(g_rooms_path, "wb");
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
    fclose(f);
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

    pthread_mutex_lock(&room_lock);
    if (find_room(name)) {
        pthread_mutex_unlock(&room_lock);
        return ROOM_CREATE_EXISTS;
    }

    room_t *r = (room_t *)calloc(1, sizeof(room_t));
    if (!r) {
        pthread_mutex_unlock(&room_lock);
        return ROOM_CREATE_INVALID;
    }
    strncpy(r->name, name, MAX_ROOM_NAME - 1);
    strncpy(r->description, description ? description : "", ROOM_DESC_LEN - 1);
    strncpy(r->code, code ? code : "", ROOM_CODE_LEN - 1);
    r->next = room_list;
    room_list = r;
    room_save_locked();
    g_room_count++;

    pthread_mutex_unlock(&room_lock);
    LOG_INFO("Room '%s' created and persisted", name);
    return ROOM_CREATE_OK;
}

int room_delete(const char *name) {
    if (!name) return ROOM_DELETE_NOTFOUND;

    pthread_mutex_lock(&room_lock);
    room_t *prev = NULL, *r = room_list;
    while (r && strcmp(r->name, name) != 0) { prev = r; r = r->next; }
    if (!r) {
        pthread_mutex_unlock(&room_lock);
        return ROOM_DELETE_NOTFOUND;
    }

    // Evict members: tell them the room is closed and move them back to
    // STATE_AUTHENTICATED so they can pick another room (single shared
    // transition relation - same event the Kripke model uses).
    char notice[160];
    snprintf(notice, sizeof(notice),
             "{\"type\":\"ROOM_CLOSED\",\"room\":\"%s\"}", name);
    for (int i = 0; i < r->num_clients; i++) {
        client_t *c = r->clients[i];
        if (!c) continue;

        /* Every member in this array is STATE_IN_ROOM: room_join_commit()
         * sets membership and state together under room_lock, and room_leave()
         * removes the member before changing state. The guard is therefore a
         * defensive invariant check, not a case that is expected to trigger -
         * ROOM_CLOSED is only legal from STATE_IN_ROOM. */
        if (c->state == STATE_IN_ROOM) {
            client_send_ws_text(c, notice);
            if (!client_state_apply(&c->state, CLIENT_EVENT_ROOM_CLOSED)) {
                // Membership implies STATE_IN_ROOM, so the model says this
                // cannot fail. If it ever did, clearing c->room alone would
                // strand the client: JOIN needs STATE_AUTHENTICATED and
                // LEAVE returns early on an empty room name, so it could
                // never recover.
                LOG_ERR("Evict '%s' from room '%s': unexpected state %s",
                        c->nickname, name, client_state_name(c->state));
                c->state = STATE_AUTHENTICATED;
            }
        }
        c->room[0] = '\0';
    }
    r->num_clients = 0;

    if (prev) prev->next = r->next;
    else room_list = r->next;
    free(r);
    room_save_locked();
    g_room_count--;
    pthread_mutex_unlock(&room_lock);
    LOG_INFO("Room '%s' deleted and persisted", name);
    return ROOM_DELETE_OK;
}

int room_leave(const char *room_name, const char *nickname) {
    if (!room_name || !nickname) return -1;

    pthread_mutex_lock(&room_lock);

    room_t *room = find_room(room_name);
    if (!room) { pthread_mutex_unlock(&room_lock); return -1; }

    for (int i = 0; i < room->num_clients; i++) {
        if (strcmp(room->clients[i]->nickname, nickname) == 0) {
            for (int j = i; j < room->num_clients - 1; j++) {
                room->clients[j] = room->clients[j + 1];
            }
            room->num_clients--;
            break;
        }
    }

    // Rooms are persisted, so an empty room is kept (not destroyed).

    pthread_mutex_unlock(&room_lock);
    return 0;
}

int room_join_commit(const char *room_name, const char *nickname,
                     struct client *client, const char *code) {
    if (!room_name || !nickname || !client) return ROOM_JOIN_NOTFOUND;

    pthread_mutex_lock(&room_lock);

    // Everything that can reject the join is checked while holding the lock,
    // so nothing can change between the checks, the membership update and the
    // state transition.
    if (client->state != STATE_AUTHENTICATED) {
        pthread_mutex_unlock(&room_lock);
        return ROOM_JOIN_BADSTATE;
    }

    room_t *room = find_room(room_name);
    if (!room) {
        pthread_mutex_unlock(&room_lock);
        return ROOM_JOIN_NOTFOUND;
    }

    if (room->code[0] != '\0') {
        if (!code || strcmp(code, room->code) != 0) {
            pthread_mutex_unlock(&room_lock);
            return ROOM_JOIN_BADCODE;
        }
    }

    if (room->num_clients >= MAX_CLIENTS_PER_ROOM) {
        pthread_mutex_unlock(&room_lock);
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
        pthread_mutex_unlock(&room_lock);
        return ROOM_JOIN_BADSTATE;
    }

    pthread_mutex_unlock(&room_lock);
    return ROOM_JOIN_OK;
}

void room_broadcast(const char *room_name, const char *exclude_nick,
                    const char *msg, int exclude_fd) {
    (void)exclude_fd;
    if (!room_name || !msg) return;

    pthread_mutex_lock(&room_lock);

    room_t *room = find_room(room_name);
    if (!room) { pthread_mutex_unlock(&room_lock); return; }

    for (int i = 0; i < room->num_clients; i++) {
        struct client *c = room->clients[i];
        if (exclude_nick && strcmp(c->nickname, exclude_nick) == 0) continue;
        client_send_ws_text(c, msg);
    }

    pthread_mutex_unlock(&room_lock);
}

void room_get_users(const char *room_name, char *out_buf, size_t out_buf_size) {
    if (!room_name || !out_buf || out_buf_size < 3) return;

    pthread_mutex_lock(&room_lock);

    room_t *room = find_room(room_name);
    if (!room) {
        strcpy(out_buf, "[]");
        pthread_mutex_unlock(&room_lock);
        return;
    }

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

    pthread_mutex_unlock(&room_lock);
}

void room_list_json(char *out_buf, size_t out_buf_size) {
    if (!out_buf || out_buf_size < 8) return;

    pthread_mutex_lock(&room_lock);

    // Always reserve space for the longest possible tail so the JSON is
    // closed properly even when the list does not fit (it stays parseable
    // and reports that entries were omitted).
    const size_t tail_reserve = sizeof(",\"truncated\":true}]}");
    bool first = true;
    bool truncated = false;
    size_t pos = 0;

    int n = snprintf(out_buf, out_buf_size, "{\"type\":\"ROOM_LIST\",\"rooms\":[");
    if (n > 0) pos = (size_t)n;

    for (room_t *r = room_list; r; r = r->next) {
        // The description is free-form admin text: it MUST be escaped or a
        // quote inside it would break the whole ROOM_LIST for every client.
        char desc[ROOM_DESC_LEN * 6 + 1];
        json_escape(r->description, desc, sizeof(desc));

        char entry[MAX_ROOM_NAME + sizeof(desc) + 128];
        int en = snprintf(entry, sizeof(entry),
            "%s{\"name\":\"%s\",\"desc\":\"%s\",\"members\":%d,\"code\":%s}",
            first ? "" : ",", r->name, desc, r->num_clients,
            r->code[0] ? "true" : "false");
        if (en <= 0) continue;

        size_t need = (size_t)en;
        if (pos + need + tail_reserve >= out_buf_size) { truncated = true; break; }
        memcpy(out_buf + pos, entry, need);
        pos += need;
        first = false;
    }

    if (truncated) {
        snprintf(out_buf + pos, out_buf_size - pos, "],\"truncated\":true}");
    } else {
        snprintf(out_buf + pos, out_buf_size - pos, "]}");
    }

    pthread_mutex_unlock(&room_lock);
}

void room_print_console(void) {
    pthread_mutex_lock(&room_lock);
    log_emit(2, NULL, 0, "  %-14s %-8s %-6s %s", "ROOM", "MEMBERS", "CODE", "DESCRIPTION");
    log_emit(2, NULL, 0, "  %-14s %-8s %-6s %s", "----", "-------", "----", "-----------");
    for (room_t *r = room_list; r; r = r->next) {
        log_emit(2, NULL, 0, "  %-14s %-8d %-6s %s", r->name, r->num_clients,
                 r->code[0] ? "yes" : "-", r->description);
    }
    pthread_mutex_unlock(&room_lock);
}

int room_count(void) {
    // Lock-free: safe to call from the console renderer while room_lock is held.
    return g_room_count;
}

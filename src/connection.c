#include "connection.h"
#include "http_upgrade.h"
#include "room.h"
#include "auth.h"
#include "session.h"
#include "json_util.h"
#include <stdlib.h>
#include "state_machine.h"

// Leave the current room (if any): notify the others and clear room state.
static void client_leave_room(client_t *client);
// Send the JOINED confirmation with the current member list.
static void send_joined(client_t *client, const char *room);

// ---------------------------------------------------------------------------
// Outbound queue (producer/consumer)
//
// Producer: any thread may call client_send_ws_text(), which encodes the frame
// and copies it into the client's ring buffer. This is a bounded memcpy and
// never touches the network, so it is safe to call while holding a room lock.
//
// Consumer: one writer thread per client owns send(). It drains the ring
// buffer with a blocking send() that carries SO_SNDTIMEO, so a peer that stops
// reading blocks only its own writer and is eventually disconnected - it can
// no longer freeze every room.
//
// Lifecycle: the client object is freed only after the writer thread has been
// joined, so the queue is never touched after free. client_destroy() first
// leaves the room (which takes the room lock, so no further enqueue can target
// this client), then stops and joins the writer.
// ---------------------------------------------------------------------------

static void writer_deadline(struct timespec *ts, int ms) {
    struct timespec now;
    // winpthreads provides clock_gettime on MinGW; pthread_cond_timedwait
    // there uses CLOCK_REALTIME by default.
    clock_gettime(CLOCK_REALTIME, &now);
    ts->tv_sec  = now.tv_sec + ms / 1000;
    ts->tv_nsec = now.tv_nsec + (long)(ms % 1000) * 1000000L;
    if (ts->tv_nsec >= 1000000000L) { ts->tv_sec++; ts->tv_nsec -= 1000000000L; }
}

// Copy an encoded frame into the queue. Returns 1 on success, 0 if the client
// is going away or the backlog is already over the limit (slow consumer).
static int client_enqueue(client_t *c, const uint8_t *data, size_t n) {
    if (!c || !c->out_buf) return 0;

    pthread_mutex_lock(&c->out_mu);

    if (c->out_stop || c->out_kick) {
        pthread_mutex_unlock(&c->out_mu);
        return 0;
    }
    if (c->out_len + n > CLIENT_OUT_QUEUE) {
        // Slow consumer policy: rather than growing without bound, mark the
        // client for disconnection. Dropping messages would silently corrupt
        // the chat, so kicking is the honest choice.
        c->out_kick = 1;
        pthread_cond_signal(&c->out_cv);
        pthread_mutex_unlock(&c->out_mu);
        return 0;
    }

    size_t tail  = (c->out_head + c->out_len) % CLIENT_OUT_QUEUE;
    size_t first = CLIENT_OUT_QUEUE - tail;
    if (first > n) first = n;
    memcpy(c->out_buf + tail, data, first);
    if (n > first) memcpy(c->out_buf, data + first, n - first);
    c->out_len += n;

    pthread_cond_signal(&c->out_cv);
    pthread_mutex_unlock(&c->out_mu);
    return 1;
}

static void *client_writer_thread(void *arg) {
    client_t *c = (client_t *)arg;

    pthread_mutex_lock(&c->out_mu);
    for (;;) {
        while (c->out_len == 0 && !c->out_stop && !c->out_kick) {
            struct timespec ts;
            writer_deadline(&ts, CLIENT_SEND_TIMEOUT_SECS * 1000);
            pthread_cond_timedwait(&c->out_cv, &c->out_mu, &ts);
        }
        if (c->out_stop || c->out_kick) break;

        // Send only the contiguous region from the head. The buffer is freed
        // by the producer at the tail, so reading here never overlaps writes.
        size_t first = CLIENT_OUT_QUEUE - c->out_head;
        if (first > c->out_len) first = c->out_len;
        const uint8_t *p = c->out_buf + c->out_head;
        int fd = c->fd;

        // Crucially, send() runs OUTSIDE out_mu so a stuck peer cannot make
        // the producer (and therefore the room lock) wait.
        pthread_mutex_unlock(&c->out_mu);
        ssize_t k = send(fd, (const char *)p, first, 0);
        pthread_mutex_lock(&c->out_mu);

        if (k > 0) {
            c->out_head = (c->out_head + (size_t)k) % CLIENT_OUT_QUEUE;
            c->out_len -= (size_t)k;
        } else if (k < 0 && socket_send_would_block()) {
            // Timed out: keep the bytes and retry on the next wake.
        } else {
            c->out_kick = 1;
            break;
        }
    }
    int kick = c->out_kick;
    pthread_mutex_unlock(&c->out_mu);

    // Wake the reader thread so the client is torn down through the normal
    // path. shutdown() also unblocks a send() still in progress.
    if (kick) {
        LOG_ERR("Disconnecting fd=%d: slow consumer (outbound queue overflow)"
                " or send failure", c->fd);
        SHUTDOWN_BOTH(c->fd);
    }
    return NULL;
}

int client_start_writer(client_t *client) {
    if (!client) return -1;
    if (pthread_create(&client->writer_tid, NULL,
                       client_writer_thread, client) != 0) {
        return -1;
    }
    client->writer_started = 1;
    return 0;
}

client_t *client_create(int fd) {
    client_t *c = (client_t *)calloc(1, sizeof(client_t));
    if (!c) return NULL;
    c->fd = fd;
    c->state = client_state_initial();
    c->last_active = time(NULL);

    pthread_mutex_init(&c->out_mu, NULL);
    pthread_cond_init(&c->out_cv, NULL);
    c->out_buf = (uint8_t *)malloc(CLIENT_OUT_QUEUE);
    if (!c->out_buf) {
        pthread_mutex_destroy(&c->out_mu);
        pthread_cond_destroy(&c->out_cv);
        free(c);
        return NULL;
    }
    return c;
}

void client_destroy(client_t *client) {
    if (!client) return;

    // Leave the room first: it takes the room lock, so once it returns no
    // producer can enqueue to this client any more.
    client_leave_room(client);

    // Release the account's session so it can log in again
    if (client->nickname[0] &&
        (client->state == STATE_AUTHENTICATED || client->state == STATE_IN_ROOM)) {
        session_remove(client->nickname);
    }

    // Ch1: DISCONNECT -> STATE_CLOSED (terminal).
    client_state_apply(&client->state, CLIENT_EVENT_DISCONNECT);

    // Stop and join the writer before freeing anything it can touch. shutdown
    // first, so a writer parked in send() returns immediately.
    if (client->writer_started) {
        pthread_mutex_lock(&client->out_mu);
        client->out_stop = 1;
        pthread_cond_signal(&client->out_cv);
        pthread_mutex_unlock(&client->out_mu);
        SHUTDOWN_BOTH(client->fd);
        pthread_join(client->writer_tid, NULL);
    }

    CLOSE_SOCKET(client->fd);

    free(client->out_buf);
    pthread_mutex_destroy(&client->out_mu);
    pthread_cond_destroy(&client->out_cv);
    free(client);
}

int client_send_ws_text(client_t *client, const char *text) {
    if (!client || !text) return -1;
    uint8_t buf[MAX_MSG_LEN * 2 + 16];
    int len = ws_frame_encode(WS_OPCODE_TEXT, (const uint8_t *)text,
                              strlen(text), false, buf, sizeof(buf));
    if (len <= 0) return -1;
    return client_enqueue(client, buf, (size_t)len) ? len : -1;
}

int client_send_close(client_t *client) {
    if (!client) return -1;
    uint8_t buf[16];
    int len = ws_frame_encode(WS_OPCODE_CLOSE, NULL, 0, false, buf, sizeof(buf));
    if (len <= 0) return -1;
    return client_enqueue(client, buf, (size_t)len) ? len : -1;
}

static void client_leave_room(client_t *client) {
    if (client->state != STATE_IN_ROOM || client->room[0] == '\0') return;
    char notice[256];
    snprintf(notice, sizeof(notice),
        "{\"type\":\"USER_LEAVE\",\"room\":\"%s\",\"user\":\"%s\"}",
        client->room, client->nickname);
    room_broadcast(client->room, client, notice);
    room_leave(client->room, client);
    LOG_INFO("'%s' left room '%s'", client->nickname, client->room);
    client->room[0] = '\0';

    // Ch1 foundation: every runtime state change goes through the
    // shared transition relation used by the Kripke model/BMC.
    if (!client_state_apply(&client->state, CLIENT_EVENT_LEAVE_OK)) {
        LOG_ERR("Illegal state transition on LEAVE: %s",
                client_state_name(client->state));
    }
}

static void send_joined(client_t *client, const char *room) {
    char users_list[MAX_MSG_LEN];
    room_get_users(room, users_list, sizeof(users_list));
    char resp[MAX_MSG_LEN + 256];
    snprintf(resp, sizeof(resp),
        "{\"type\":\"JOINED\",\"room\":\"%s\",\"users\":%s}", room, users_list);
    client_send_ws_text(client, resp);
}

static int handle_http_handshake(client_t *client) {
    http_request_t req;
    int result = http_parse_request(client->read_buf, client->read_len, &req);

    if (result == 0) return 0; // need more data
    if (result < 0) {
        LOG_ERR("fd=%d HTTP parse failed", client->fd);
        return -1; // bad request
    }

    if (!req.valid || !http_validate_key(req.websocket_key)) {
        LOG_ERR("Invalid WebSocket handshake from fd %d", client->fd);
        return -1;
    }

    // Build upgrade response
    char resp[512];
    int resp_len = http_build_upgrade_response(req.websocket_key, resp, sizeof(resp));
    if (resp_len <= 0) return -1;

    send(client->fd, resp, resp_len, 0);

    // Consume only the HTTP request bytes; keep any pipelined WebSocket
    // frame that arrived in the same TCP segment.
    size_t consumed = req.header_len;
    if (consumed > (size_t)client->read_len) consumed = (size_t)client->read_len;
    if (consumed < (size_t)client->read_len) {
        memmove(client->read_buf, client->read_buf + consumed,
                (size_t)client->read_len - consumed);
    }
    client->read_len -= (int)consumed;
    client->read_buf[client->read_len] = '\0';

    if (!client_state_apply(&client->state, CLIENT_EVENT_HTTP_UPGRADE_OK)) {
        LOG_ERR("Illegal state transition after WebSocket upgrade: %s",
                client_state_name(client->state));
        return -1;
    }

    LOG_INFO("Client fd=%d upgraded to WebSocket (%s)",
             client->fd, client_state_name(client->state));
    return 1;
}

static int handle_ws_message(client_t *client, ws_frame_t *frame) {
    if (frame->opcode == WS_OPCODE_CLOSE) {
        client_send_close(client);
        return -1;
    }

    if (frame->opcode == WS_OPCODE_PING) {
        uint8_t pong_buf[16];
        int len = ws_frame_encode(WS_OPCODE_PONG, frame->payload,
                                  frame->payload_len, false, pong_buf, sizeof(pong_buf));
        if (len > 0) client_enqueue(client, pong_buf, (size_t)len);
        return 0;
    }

    if (frame->opcode == WS_OPCODE_PONG) return 0;

    if (frame->opcode != WS_OPCODE_TEXT) return 0;

    // Null-terminate payload for JSON parsing
    char *msg = NULL;
    if (frame->payload_len > 0) {
        msg = (char *)malloc(frame->payload_len + 1);
        if (!msg) return -1;
        memcpy(msg, frame->payload, frame->payload_len);
        msg[frame->payload_len] = '\0';
    }

    if (!msg) return 0;

    // Dispatch on the "type" field of the JSON command.
    char msg_type[32] = {0};
    if (json_get_string(msg, "type", msg_type, sizeof(msg_type)) != 0) {
        free(msg);
        return 0;
    }

    if (strcmp(msg_type, "REGISTER") == 0) {
        if (client->state != STATE_WS_CONNECTED) {
            client_send_ws_text(client, "{\"type\":\"REGISTER_FAIL\",\"msg\":\"Already logged in\"}");
            free(msg);
            return 0;
        }
        char username[MAX_NICKNAME] = {0};
        char password[64] = {0};
        if (json_get_string(msg, "username", username, sizeof(username)) != 0 ||
            json_get_string(msg, "password", password, sizeof(password)) != 0) {
            client_send_ws_text(client, "{\"type\":\"REGISTER_FAIL\",\"msg\":\"Missing username or password\"}");
            free(msg);
            return 0;
        }

        auth_reg_result_t r = auth_register(username, password);
        if (r == AUTH_REG_OK) {
            char resp[256];
            snprintf(resp, sizeof(resp),
                     "{\"type\":\"REGISTER_OK\",\"username\":\"%s\"}", username);
            client_send_ws_text(client, resp);
            LOG_INFO("New user registered: '%s' (fd=%d)", username, client->fd);
        } else if (r == AUTH_REG_EXISTS) {
            client_send_ws_text(client, "{\"type\":\"REGISTER_FAIL\",\"msg\":\"Username already taken\"}");
        } else if (r == AUTH_REG_IO) {
            client_send_ws_text(client, "{\"type\":\"REGISTER_FAIL\",\"msg\":\"Server storage error\"}");
        } else {
            client_send_ws_text(client, "{\"type\":\"REGISTER_FAIL\",\"msg\":\"Invalid username (3-31 chars, alnum/_) or password (min 4, no spaces)\"}");
        }
        free(msg);
        return 0;
    }
    else if (strcmp(msg_type, "LOGIN") == 0) {
        if (client->state != STATE_WS_CONNECTED) {
            client_send_ws_text(client, "{\"type\":\"ERROR\",\"msg\":\"Already logged in\"}");
            free(msg);
            return 0;
        }
        char username[MAX_NICKNAME] = {0};
        char password[64] = {0};
        if (json_get_string(msg, "username", username, sizeof(username)) != 0 ||
            json_get_string(msg, "password", password, sizeof(password)) != 0 ||
            username[0] == '\0') {
            client_send_ws_text(client, "{\"type\":\"LOGIN_FAIL\",\"msg\":\"Missing credentials\"}");
            client_state_apply(&client->state, CLIENT_EVENT_LOGIN_FAIL);
            free(msg);
            return 0;
        }

        auth_result_t ar = auth_check(username, password);
        if (ar == AUTH_LOCKED) {
            client_send_ws_text(client, "{\"type\":\"LOGIN_FAIL\",\"msg\":\"Too many failed attempts, try again later\"}");
            LOG_INFO("Login locked out for '%s' (fd=%d)", username, client->fd);
            client_state_apply(&client->state, CLIENT_EVENT_LOGIN_FAIL);
            free(msg);
            return 0;
        }
        if (ar != AUTH_OK) {
            // Same message for unknown user and wrong password (no enumeration).
            client_send_ws_text(client, "{\"type\":\"LOGIN_FAIL\",\"msg\":\"Invalid credentials\"}");
            LOG_INFO("Failed login for '%s' (fd=%d)", username, client->fd);
            client_state_apply(&client->state, CLIENT_EVENT_LOGIN_FAIL);
            free(msg);
            return 0;
        }

        // Credentials valid: acquire the single session for this account.
        session_result_t sr = session_add(username);
        if (sr != SESSION_OK) {
            const char *m = (sr == SESSION_FULL)
                ? "Server at capacity, try again later"
                : "Account already logged in elsewhere";
            char resp[160];
            snprintf(resp, sizeof(resp), "{\"type\":\"LOGIN_FAIL\",\"msg\":\"%s\"}", m);
            client_send_ws_text(client, resp);
            LOG_INFO("Session rejected for '%s' (fd=%d): %s", username, client->fd, m);
            client_state_apply(&client->state, CLIENT_EVENT_LOGIN_FAIL);
            free(msg);
            return 0;
        }

        snprintf(client->nickname, sizeof(client->nickname), "%s", username);

        if (!client_state_apply(&client->state, CLIENT_EVENT_LOGIN_OK)) {
            // Keep session bookkeeping consistent if the transition is rejected.
            session_remove(username);
            client->nickname[0] = '\0';
            client_send_ws_text(client,
                "{\"type\":\"LOGIN_FAIL\",\"msg\":\"Invalid connection state\"}");
            LOG_ERR("Illegal LOGIN transition for '%s' (fd=%d)",
                    username, client->fd);
            free(msg);
            return 0;
        }

        char resp[256];
        snprintf(resp, sizeof(resp),
                 "{\"type\":\"LOGIN_OK\",\"username\":\"%s\"}", username);
        client_send_ws_text(client, resp);
        LOG_INFO("User '%s' authenticated (fd=%d)", username, client->fd);
        free(msg);
        return 0;
    }
    else if (strcmp(msg_type, "ROOMS") == 0) {
        if (client->state != STATE_AUTHENTICATED && client->state != STATE_IN_ROOM) {
            client_send_ws_text(client, "{\"type\":\"ERROR\",\"msg\":\"Please LOGIN first\"}");
            free(msg);
            return 0;
        }
        // Optional pagination cursor: ROOMS {"offset":N}.
        int offset = 0;
        long off = 0;
        if (json_get_int(msg, "offset", &off) == 0 && off > 0)
            offset = (int)off;

        char list[MAX_MSG_LEN];
        int has_more = 0;
        room_list_page_json(list, sizeof(list), offset, ROOMS_PAGE, &has_more);
        client_send_ws_text(client, list);
    }
    else if (strcmp(msg_type, "JOIN") == 0) {
        // Design: switching rooms requires leaving the current one first, so
        // JOIN is only valid from STATE_AUTHENTICATED (matches the Kripke R).
        if (client->state == STATE_IN_ROOM) {
            client_send_ws_text(client,
                "{\"type\":\"JOIN_FAIL\",\"msg\":\"Leave your current room first\"}");
            free(msg);
            return 0;
        }
        if (client->state != STATE_AUTHENTICATED) {
            client_send_ws_text(client, "{\"type\":\"ERROR\",\"msg\":\"Please LOGIN first\"}");
            free(msg);
            return 0;
        }
        char room_name[MAX_ROOM_NAME] = {0};
        char code[32] = {0};
        if (json_get_string(msg, "room", room_name, sizeof(room_name)) != 0 ||
            room_name[0] == '\0') {
            client_send_ws_text(client, "{\"type\":\"JOIN_FAIL\",\"msg\":\"Invalid room\"}");
            free(msg);
            return 0;
        }
        json_get_string(msg, "code", code, sizeof(code));   // optional

        const char *nickname = client->nickname;

        // One atomic operation: validation, membership, room reference and the
        // AUTHENTICATED -> IN_ROOM transition all happen under the room lock. The
        // console thread's room_delete() needs the same lock, so it can no
        // longer land in the middle of a join and strand the client.
        int jr = room_join_commit(room_name, client, code);
        if (jr == ROOM_JOIN_OK) {
            send_joined(client, room_name);

            // Notify others
            char notify[MAX_MSG_LEN];
            snprintf(notify, sizeof(notify),
                "{\"type\":\"USER_JOIN\",\"room\":\"%s\",\"user\":\"%s\"}",
                room_name, nickname);
            room_broadcast(room_name, client, notify);

            LOG_INFO("'%s' joined room '%s'", nickname, room_name);
        } else {
            const char *reason = "Cannot join room";
            if (jr == ROOM_JOIN_BADCODE)        reason = "Wrong or missing room code";
            else if (jr == ROOM_JOIN_NOTFOUND)  reason = "Room does not exist";
            else if (jr == ROOM_JOIN_FULL)      reason = "Room is full";
            else if (jr == ROOM_JOIN_BADSTATE)  reason = "Invalid connection state";
            char resp[MAX_MSG_LEN];
            snprintf(resp, sizeof(resp),
                "{\"type\":\"JOIN_FAIL\",\"room\":\"%s\",\"msg\":\"%s\"}",
                room_name, reason);
            client_send_ws_text(client, resp);
            if (client->state == STATE_AUTHENTICATED) {
                client_state_apply(&client->state, CLIENT_EVENT_JOIN_FAIL);
            }
        }
    }
    else if (strcmp(msg_type, "LEAVE") == 0) {
        if (client->state != STATE_IN_ROOM) {
            client_send_ws_text(client, "{\"type\":\"LEFT\"}");
            free(msg);
            return 0;
        }
        client_leave_room(client);
        client_send_ws_text(client, "{\"type\":\"LEFT\"}");
    }
    else if (strcmp(msg_type, "LOGOUT") == 0) {
        // Release the session without dropping the connection. If the client
        // is in a room, leave it first (LEAVE_OK -> AUTHENTICATED), then log out.
        if (client->state == STATE_IN_ROOM) {
            client_leave_room(client);
        }
        if (client->state != STATE_AUTHENTICATED) {
            client_send_ws_text(client, "{\"type\":\"ERROR\",\"msg\":\"Not logged in\"}");
            free(msg);
            return 0;
        }

        char who[MAX_NICKNAME] = {0};
        snprintf(who, sizeof(who), "%s", client->nickname);
        session_remove(who);
        client->nickname[0] = '\0';

        if (!client_state_apply(&client->state, CLIENT_EVENT_LOGOUT)) {
            LOG_ERR("Illegal LOGOUT transition for '%s' (fd=%d)", who, client->fd);
        }
        client_send_ws_text(client, "{\"type\":\"LOGGED_OUT\"}");
        LOG_INFO("User '%s' logged out (fd=%d)", who, client->fd);
    }
    else if (strcmp(msg_type, "MESSAGE") == 0) {
        if (client->state != STATE_IN_ROOM) {
            client_send_ws_text(client, "{\"type\":\"ERROR\",\"msg\":\"Not in a room\"}");
            free(msg);
            return 0;
        }
        char content[MAX_MSG_LEN] = {0};
        if (json_get_string(msg, "content", content, sizeof(content)) != 0) {
            free(msg);
            return 0;
        }

        char esc[MAX_MSG_LEN * 2];
        json_escape(content, esc, sizeof(esc));

        char resp[MAX_MSG_LEN * 2 + 256];
        snprintf(resp, sizeof(resp),
            "{\"type\":\"MESSAGE\",\"from\":\"%s\",\"room\":\"%s\",\"content\":\"%s\"}",
            client->nickname, client->room, esc);
        room_broadcast(client->room, NULL, resp);
        // Message content is intentionally NOT logged (volume + privacy).
    }
    else if (strcmp(msg_type, "LIST") == 0) {
        if (client->state != STATE_IN_ROOM) {
            client_send_ws_text(client, "{\"type\":\"ERROR\",\"msg\":\"Not in a room\"}");
            free(msg);
            return 0;
        }
        char users_list[MAX_MSG_LEN];
        room_get_users(client->room, users_list, sizeof(users_list));
        char resp[MAX_MSG_LEN + 256];
        snprintf(resp, sizeof(resp),
            "{\"type\":\"USER_LIST\",\"room\":\"%s\",\"users\":%s}",
            client->room, users_list);
        client_send_ws_text(client, resp);
    }
    else if (strcmp(msg_type, "PING") == 0) {
        client_send_ws_text(client, "{\"type\":\"PONG\"}");
    }

    free(msg);
    return 0;
}

int client_process_buffer(client_t *client) {
    while (client->read_len > 0) {
        if (client->state == STATE_IDLE) {
            // First bytes arrived: leave IDLE (Ch1: IDLE --accept--> HTTP_HANDSHAKE).
            client_state_apply(&client->state, CLIENT_EVENT_ACCEPT);
        }
        if (client->state == STATE_HTTP_HANDSHAKE) {
            int r = handle_http_handshake(client);
            if (r <= 0) return r;
            // continue to process remaining buffer as WS frames
            continue;
        }

        // Parse WebSocket frame
        ws_frame_t frame;
        memset(&frame, 0, sizeof(frame));
        int consumed = ws_frame_decode((uint8_t *)client->read_buf,
                                        client->read_len, &frame);
        if (consumed <= 0) {
            if (consumed < 0) return -1;
            return 0; // need more data
        }

        int r = handle_ws_message(client, &frame);
        ws_frame_free(&frame);

        // Remove consumed bytes from buffer
        if (consumed < client->read_len) {
            memmove(client->read_buf, client->read_buf + consumed,
                    client->read_len - consumed);
        }
        client->read_len -= consumed;
        client->read_buf[client->read_len] = '\0';

        if (r != 0) return r;
    }
    return 0;
}

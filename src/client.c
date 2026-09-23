#include "client.h"
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

// Admin key used to authorize room provisioning (CREATE_ROOM).
static const char *admin_key(void) {
    static char key[64] = {0};
    if (!key[0]) {
        const char *env = getenv("WSCHAT_ADMIN_KEY");
        snprintf(key, sizeof(key), "%s", (env && env[0]) ? env : "admin123");
    }
    return key;
}

client_t *client_create(int fd) {
    client_t *c = (client_t *)calloc(1, sizeof(client_t));
    if (!c) return NULL;
    c->fd = fd;
    c->state = client_state_initial();
    return c;
}

void client_destroy(client_t *client) {
    if (!client) return;
    client_leave_room(client);
    // Release the account's session so it can log in again
    if (client->nickname[0] &&
        (client->state == STATE_AUTHENTICATED || client->state == STATE_IN_ROOM)) {
        session_remove(client->nickname);
    }
    CLOSE_SOCKET(client->fd);
    free(client);
}

int client_send_ws_text(client_t *client, const char *text) {
    if (!client || !text) return -1;
    uint8_t buf[MAX_MSG_LEN * 2 + 16];
    int len = ws_frame_encode(WS_OPCODE_TEXT, (const uint8_t *)text,
                              strlen(text), false, buf, sizeof(buf));
    if (len <= 0) return -1;
    return send(client->fd, (const char *)buf, len, 0);
}

int client_send_close(client_t *client) {
    if (!client) return -1;
    uint8_t buf[16];
    int len = ws_frame_encode(WS_OPCODE_CLOSE, NULL, 0, false, buf, sizeof(buf));
    if (len <= 0) return -1;
    return send(client->fd, (const char *)buf, len, 0);
}

static void client_leave_room(client_t *client) {
    if (client->state != STATE_IN_ROOM || client->room[0] == '\0') return;
    char notice[256];
    snprintf(notice, sizeof(notice),
        "{\"type\":\"USER_LEAVE\",\"room\":\"%s\",\"user\":\"%s\"}",
        client->room, client->nickname);
    room_broadcast(client->room, client->nickname, notice, -1);
    room_leave(client->room, client->nickname);
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

    // Clear read buffer
    client->read_len = 0;
    client->read_buf[0] = '\0';

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
        if (len > 0) send(client->fd, (const char *)pong_buf, len, 0);
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
            free(msg);
            return 0;
        }

        if (auth_check(username, password)) {
            // Enforce a single active session per account
            if (!session_add(username)) {
                client_send_ws_text(client, "{\"type\":\"LOGIN_FAIL\",\"msg\":\"Account already logged in elsewhere\"}");
                LOG_INFO("Duplicate login rejected for '%s' (fd=%d)", username, client->fd);
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
        } else {
            client_send_ws_text(client, "{\"type\":\"LOGIN_FAIL\",\"msg\":\"Invalid credentials\"}");
            LOG_INFO("Failed login for '%s' (fd=%d)", username, client->fd);
        }
        free(msg);
        return 0;
    }
    else if (strcmp(msg_type, "ROOMS") == 0) {
        char admin[64] = {0};
        json_get_string(msg, "admin", admin, sizeof(admin));
        int is_admin = (admin[0] && strcmp(admin, admin_key()) == 0);

        if (!is_admin && client->state != STATE_AUTHENTICATED &&
            client->state != STATE_IN_ROOM) {
            client_send_ws_text(client, "{\"type\":\"ERROR\",\"msg\":\"Please LOGIN first\"}");
            free(msg);
            return 0;
        }
        char list[MAX_MSG_LEN];
        room_list_json(list, sizeof(list));
        client_send_ws_text(client, list);
    }
    else if (strcmp(msg_type, "CREATE_ROOM") == 0) {
        char admin[64] = {0};
        char name[MAX_ROOM_NAME] = {0};
        char desc[160] = {0};
        char code[16] = {0};

        json_get_string(msg, "admin", admin, sizeof(admin));
        if (strcmp(admin, admin_key()) != 0) {
            client_send_ws_text(client, "{\"type\":\"ROOM_CREATE_FAIL\",\"msg\":\"unauthorized\"}");
            LOG_INFO("Rejected CREATE_ROOM from fd=%d (bad admin key)", client->fd);
            free(msg);
            return 0;
        }
        json_get_string(msg, "name", name, sizeof(name));
        json_get_string(msg, "desc", desc, sizeof(desc));
        json_get_string(msg, "code", code, sizeof(code));

        int rr = room_create(name, desc, code);
        char resp[512];
        if (rr == ROOM_CREATE_OK) {
            snprintf(resp, sizeof(resp),
                     "{\"type\":\"ROOM_CREATED\",\"name\":\"%s\"}", name);
            LOG_INFO("Room '%s' provisioned by admin (fd=%d)", name, client->fd);
        } else if (rr == ROOM_CREATE_EXISTS) {
            snprintf(resp, sizeof(resp),
                     "{\"type\":\"ROOM_CREATE_FAIL\",\"name\":\"%s\",\"msg\":\"already exists\"}", name);
        } else {
            snprintf(resp, sizeof(resp),
                     "{\"type\":\"ROOM_CREATE_FAIL\",\"name\":\"%s\",\"msg\":\"invalid name\"}", name);
        }
        client_send_ws_text(client, resp);
        free(msg);
        return 0;
    }
    else if (strcmp(msg_type, "DELETE_ROOM") == 0) {
        char admin[64] = {0};
        char name[MAX_ROOM_NAME] = {0};

        json_get_string(msg, "admin", admin, sizeof(admin));
        if (strcmp(admin, admin_key()) != 0) {
            client_send_ws_text(client, "{\"type\":\"ROOM_DELETE_FAIL\",\"msg\":\"unauthorized\"}");
            free(msg);
            return 0;
        }
        json_get_string(msg, "name", name, sizeof(name));

        int dr = room_delete(name);
        char resp[512];
        if (dr == ROOM_DELETE_OK) {
            snprintf(resp, sizeof(resp),
                     "{\"type\":\"ROOM_DELETED\",\"name\":\"%s\"}", name);
            LOG_INFO("Room '%s' deleted by admin (fd=%d)", name, client->fd);
        } else {
            snprintf(resp, sizeof(resp),
                     "{\"type\":\"ROOM_DELETE_FAIL\",\"name\":\"%s\",\"msg\":\"not found\"}", name);
        }
        client_send_ws_text(client, resp);
        free(msg);
        return 0;
    }
    else if (strcmp(msg_type, "JOIN") == 0) {
        if (client->state != STATE_AUTHENTICATED && client->state != STATE_IN_ROOM) {
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

        // Already in this room: just resend the confirmation
        if (client->state == STATE_IN_ROOM && strcmp(client->room, room_name) == 0) {
            send_joined(client, room_name);
            free(msg);
            return 0;
        }

        // Moving to another room: leave the current one first
        client_leave_room(client);

        int jr = room_join(room_name, nickname, client, code);
        if (jr == ROOM_JOIN_OK) {
            snprintf(client->room, sizeof(client->room), "%s", room_name);

            if (!client_state_apply(&client->state, CLIENT_EVENT_JOIN_OK)) {
                // Roll back room membership if the formal transition rejects JOIN.
                room_leave(room_name, nickname);
                client->room[0] = '\0';
                client_send_ws_text(client,
                    "{\"type\":\"JOIN_FAIL\",\"msg\":\"Invalid connection state\"}");
                LOG_ERR("Illegal JOIN transition for '%s' -> room '%s'",
                        nickname, room_name);
                free(msg);
                return 0;
            }

            send_joined(client, room_name);

            // Notify others
            char notify[MAX_MSG_LEN];
            snprintf(notify, sizeof(notify),
                "{\"type\":\"USER_JOIN\",\"room\":\"%s\",\"user\":\"%s\"}",
                room_name, nickname);
            room_broadcast(room_name, nickname, notify, -1);

            LOG_INFO("'%s' joined room '%s'", nickname, room_name);
        } else {
            const char *reason = "Cannot join room";
            if (jr == ROOM_JOIN_BADCODE)        reason = "Wrong or missing room code";
            else if (jr == ROOM_JOIN_NOTFOUND)  reason = "Room does not exist";
            else if (jr == ROOM_JOIN_FULL)      reason = "Room is full";
            char resp[MAX_MSG_LEN];
            snprintf(resp, sizeof(resp),
                "{\"type\":\"JOIN_FAIL\",\"room\":\"%s\",\"msg\":\"%s\"}",
                room_name, reason);
            client_send_ws_text(client, resp);
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

        char resp[MAX_MSG_LEN + 256];
        snprintf(resp, sizeof(resp),
            "{\"type\":\"MESSAGE\",\"from\":\"%s\",\"room\":\"%s\",\"content\":\"%s\"}",
            client->nickname, client->room, content);
        room_broadcast(client->room, NULL, resp, -1);
        LOG_INFO("[%s] %s: %s", client->room, client->nickname, content);
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

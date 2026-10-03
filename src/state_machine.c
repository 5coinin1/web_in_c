#include "state_machine.h"

client_state_t client_state_initial(void)
{
    return STATE_IDLE;
}

bool client_state_next(client_state_t current,
                       client_event_t event,
                       client_state_t *next)
{
    if (!next)
        return false;

    switch (current)
    {
    case STATE_IDLE:
        if (event == CLIENT_EVENT_ACCEPT)
        {
            *next = STATE_HTTP_HANDSHAKE;
            return true;
        }
        if (event == CLIENT_EVENT_DISCONNECT)
        {
            *next = STATE_CLOSED;
            return true;
        }
        return false;

    case STATE_HTTP_HANDSHAKE:
        if (event == CLIENT_EVENT_HTTP_UPGRADE_OK)
        {
            *next = STATE_WS_CONNECTED;
            return true;
        }
        if (event == CLIENT_EVENT_DISCONNECT)
        {
            *next = STATE_CLOSED;
            return true;
        }
        return false;

    case STATE_WS_CONNECTED:
        if (event == CLIENT_EVENT_LOGIN_OK)
        {
            *next = STATE_AUTHENTICATED;
            return true;
        }
        if (event == CLIENT_EVENT_LOGIN_FAIL)
        {
            *next = STATE_WS_CONNECTED;
            return true;
        }
        if (event == CLIENT_EVENT_DISCONNECT)
        {
            *next = STATE_CLOSED;
            return true;
        }
        return false;

    case STATE_AUTHENTICATED:
        if (event == CLIENT_EVENT_JOIN_OK)
        {
            *next = STATE_IN_ROOM;
            return true;
        }
        if (event == CLIENT_EVENT_JOIN_FAIL)
        {
            *next = STATE_AUTHENTICATED;
            return true;
        }
        if (event == CLIENT_EVENT_LOGOUT)
        {
            *next = STATE_WS_CONNECTED;
            return true;
        }
        if (event == CLIENT_EVENT_DISCONNECT)
        {
            *next = STATE_CLOSED;
            return true;
        }
        return false;

    case STATE_IN_ROOM:
        /* Switching rooms is NOT a transition here: a client must LEAVE
         * (IN_ROOM -> AUTHENTICATED) before it can JOIN another room. */
        if (event == CLIENT_EVENT_LEAVE_OK ||
            event == CLIENT_EVENT_ROOM_CLOSED)
        {
            *next = STATE_AUTHENTICATED;
            return true;
        }
        if (event == CLIENT_EVENT_DISCONNECT)
        {
            *next = STATE_CLOSED;
            return true;
        }
        return false;

    case STATE_CLOSED:
        return false;   // terminal: no outgoing edges

    default:
        return false;
    }
}

bool client_state_apply(client_state_t *state, client_event_t event)
{
    if (!state)
        return false;

    client_state_t next;
    if (!client_state_next(*state, event, &next))
        return false;

    *state = next;
    return true;
}

const char *client_state_name(client_state_t state)
{
    switch (state)
    {
    case STATE_IDLE:
        return "IDLE";
    case STATE_HTTP_HANDSHAKE:
        return "HTTP_HANDSHAKE";
    case STATE_WS_CONNECTED:
        return "WS_CONNECTED";
    case STATE_AUTHENTICATED:
        return "AUTHENTICATED";
    case STATE_IN_ROOM:
        return "IN_ROOM";
    case STATE_CLOSED:
        return "CLOSED";
    default:
        return "UNKNOWN";
    }
}

const char *client_event_name(client_event_t event)
{
    switch (event)
    {
    case CLIENT_EVENT_ACCEPT:
        return "ACCEPT";
    case CLIENT_EVENT_HTTP_UPGRADE_OK:
        return "HTTP_UPGRADE_OK";
    case CLIENT_EVENT_LOGIN_OK:
        return "LOGIN_OK";
    case CLIENT_EVENT_LOGIN_FAIL:
        return "LOGIN_FAIL";
    case CLIENT_EVENT_JOIN_OK:
        return "JOIN_OK";
    case CLIENT_EVENT_JOIN_FAIL:
        return "JOIN_FAIL";
    case CLIENT_EVENT_LEAVE_OK:
        return "LEAVE_OK";
    case CLIENT_EVENT_ROOM_CLOSED:
        return "ROOM_CLOSED";
    case CLIENT_EVENT_LOGOUT:
        return "LOGOUT";
    case CLIENT_EVENT_DISCONNECT:
        return "DISCONNECT";
    default:
        return "UNKNOWN_EVENT";
    }
}

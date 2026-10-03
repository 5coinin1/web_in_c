#ifndef STATE_MACHINE_H
#define STATE_MACHINE_H

#include "common.h"
#include <stdbool.h>

/*
 * Chapter 1 shared connection state machine.
 *
 * This is the SINGLE transition relation used by:
 *   1) the real server in client.c
 *   2) the Kripke model
 *   3) bounded model checking tests
 *
 * Keeping one transition relation avoids a "model says one thing,
 * implementation does another" problem.
 *
 * State-preserving ("stutter") commands are NOT edges of R - they leave the
 * state unchanged and never call client_state_apply():
 *   REGISTER (WS_CONNECTED), ROOMS (AUTH/IN_ROOM), MESSAGE/LIST (IN_ROOM),
 *   PING (any state), LEAVE from a non-room state.
 */
typedef enum
{
    CLIENT_EVENT_ACCEPT = 0,
    CLIENT_EVENT_HTTP_UPGRADE_OK,
    CLIENT_EVENT_LOGIN_OK,
    CLIENT_EVENT_LOGIN_FAIL,
    CLIENT_EVENT_JOIN_OK,
    CLIENT_EVENT_JOIN_FAIL,
    CLIENT_EVENT_LEAVE_OK,
    CLIENT_EVENT_ROOM_CLOSED,
    CLIENT_EVENT_LOGOUT,
    CLIENT_EVENT_DISCONNECT,
    CLIENT_EVENT_COUNT
} client_event_t;

/* Initial state of a newly accepted TCP client. */
client_state_t client_state_initial(void);

/*
 * Compute a transition without mutating the caller.
 * Returns true iff the event is legal from `current`.
 */
bool client_state_next(client_state_t current,
                       client_event_t event,
                       client_state_t *next);

/*
 * Apply a legal transition in place.
 * Returns false and leaves *state unchanged for an illegal transition.
 */
bool client_state_apply(client_state_t *state, client_event_t event);

const char *client_state_name(client_state_t state);
const char *client_event_name(client_event_t event);

#endif

#ifndef KRIPKE_H
#define KRIPKE_H

#include "state_machine.h"

#include <stdbool.h>
#include <stdint.h>

/*
 * ============================================================
 * Kripke Structure
 *
 * K = (S, S0, R, L)
 *
 * S:
 *   connection states from state_machine.h
 *
 * S0:
 *   STATE_HTTP_HANDSHAKE
 *
 * R:
 *   client_state_next()
 *
 * L:
 *   atomic propositions attached to each state
 * ============================================================
 */


/*
 * Atomic propositions.
 */
typedef enum {
    KRIPKE_AP_WS_OPEN       = 1u << 0,
    KRIPKE_AP_AUTHENTICATED = 1u << 1,
    KRIPKE_AP_IN_ROOM       = 1u << 2,
    KRIPKE_AP_CLOSED        = 1u << 3
} kripke_ap_t;


/*
 * Return the label L(s) of a state.
 */
uint32_t kripke_label(
    client_state_t state
);


/*
 * Check whether an atomic proposition belongs to L(s).
 */
bool kripke_has_ap(
    client_state_t state,
    kripke_ap_t proposition
);


/*
 * Safety properties.
 */

/*
 * P1:
 *
 * AG(IN_ROOM -> AUTHENTICATED)
 */
bool kripke_property_room_requires_auth(
    client_state_t state
);


/*
 * P2:
 *
 * AG(AUTHENTICATED -> WS_OPEN)
 */
bool kripke_property_auth_requires_ws(
    client_state_t state
);


/*
 * P3:
 *
 * AG(CLOSED -> !(WS_OPEN | AUTHENTICATED | IN_ROOM))
 */
bool kripke_property_closed_is_clean(
    client_state_t state
);


/*
 * Verify every invariant for one state.
 */
bool kripke_properties_hold(
    client_state_t state
);


/*
 * Explore every legal execution path up to bound k.
 *
 * true:
 *      no counterexample found.
 *
 * false:
 *      a safety property was violated.
 */
bool kripke_bmc(
    int bound,
    bool print_counterexample
);


/*
 * Liveness (possibility of progress), checked as EF reachability over R:
 *   L1: from every reachable connected state, IN_ROOM or CLOSED is reachable
 *   L2: from every reachable IN_ROOM state, AUTHENTICATED is reachable
 * Returns true iff both hold.
 */
bool kripke_liveness_holds(void);


/*
 * Completeness threshold for state reachability: the maximum shortest-path
 * distance from S0 to any reachable state. BMC on the state invariants is
 * complete for any bound >= this value.
 */
int kripke_completeness_threshold(void);


/*
 * Tier-2 model: account session (single-session), composed from two
 * connections A and B of the SAME account.
 *
 * Global state = (a_logged, b_logged) in {0,1}^2, S0 = (0,0).
 * Transitions (asynchronous interleaving):
 *   A_login : (0,0)->(1,0);  rejected (self-loop) when b_logged
 *   B_login : (0,0)->(0,1);  rejected (self-loop) when a_logged
 *   A_logout: (1,*)->(0,*);  B_logout: (*,1)->(*,0)
 *
 * kripke_session_mutex_holds(): checks AG( !(a_logged && b_logged) ).
 * kripke_session_mutex_buggy(): the same check but with the session check
 * removed (both may log in) - returns true if the violation was found.
 */
bool kripke_session_mutex_holds(void);
bool kripke_session_mutex_buggy(void);


/*
 * Tier-3 model: room product.
 *
 * Tier-1 sees one connection, Tier-2 sees two connections that only share
 * the session table. Neither can see the room, because the room is SHARED
 * data: one admin event moves every member at once.
 *
 * Global state = (a, b, a_in_room, b_in_room, members)
 *   a, b        : STATE_* of two connection roles
 *   a_in_room   : mirrors client->room[0] != '\0'
 *   b_in_room   : mirrors client->room[0] != '\0'
 *   members     : mirrors room->num_clients
 *
 * State space = 6 * 6 * 2 * 2 * 3 = 216 states.
 *
 * Invariants checked on every reachable state:
 *   I1  in_room[i] <-> state[i] == STATE_IN_ROOM
 *       (a violation strands the client: JOIN needs STATE_AUTHENTICATED
 *        and client_leave_room() returns early on an empty room name)
 *   I2  members == (a_in_room ? 1 : 0) + (b_in_room ? 1 : 0)
 *   I3  members <= 2
 *
 * Transitions: local interleaving (one role, one legal event) plus the
 * shared DELETE_ROOM step. CLIENT_EVENT_ROOM_CLOSED is not a local event
 * because the code only produces it from room_delete().
 */
typedef enum {
    ROOM_BUG_NONE = 0,
    ROOM_BUG_STRANDED_FLAG,   /* clears the room ref, keeps STATE_IN_ROOM */
    ROOM_BUG_PARTIAL_EVICT,   /* evict loop stops at the first member */
    ROOM_BUG_COUNT_NOT_RESET  /* forgets room->num_clients = 0 */
} room_bug_t;

/* Verify I1, I2 and I3 over every reachable state of the correct model. */
bool kripke_room_product_holds(void);

/* Re-run the product with a deliberately broken room_delete(). Returns
 * true when a counterexample was found, i.e. the model has teeth. */
bool kripke_room_product_counterexample(room_bug_t bug);


/*
 * Deterministic tests for the shared state machine.
 *
 * Returns:
 *     0 -> all tests passed
 *     1 -> at least one test failed
 */
int kripke_run_tests(void);

#endif
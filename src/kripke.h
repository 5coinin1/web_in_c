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
    KRIPKE_AP_IN_ROOM       = 1u << 2
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
 * Deterministic tests for the shared state machine.
 *
 * Returns:
 *     0 -> all tests passed
 *     1 -> at least one test failed
 */
int kripke_run_tests(void);

#endif
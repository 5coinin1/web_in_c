#include "kripke.h"

#include <stdio.h>
#include <string.h>

/*
 * ============================================================
 * Kripke labeling function L
 * ============================================================
 */

uint32_t kripke_label(client_state_t state)
{
    switch (state)
    {

    case STATE_HTTP_HANDSHAKE:
        return 0;

    case STATE_WS_CONNECTED:
        return KRIPKE_AP_WS_OPEN;

    case STATE_AUTHENTICATED:
        return KRIPKE_AP_WS_OPEN |
               KRIPKE_AP_AUTHENTICATED;

    case STATE_IN_ROOM:
        return KRIPKE_AP_WS_OPEN |
               KRIPKE_AP_AUTHENTICATED |
               KRIPKE_AP_IN_ROOM;

    default:
        return 0;
    }
}

bool kripke_has_ap(
    client_state_t state,
    kripke_ap_t proposition)
{
    return (kripke_label(state) &
            (uint32_t)proposition) != 0;
}

/*
 * ============================================================
 * Properties
 * ============================================================
 */

/*
 * P1:
 *
 * AG(IN_ROOM -> AUTHENTICATED)
 */
bool kripke_property_room_requires_auth(
    client_state_t state)
{
    bool in_room =
        kripke_has_ap(
            state,
            KRIPKE_AP_IN_ROOM);

    bool authenticated =
        kripke_has_ap(
            state,
            KRIPKE_AP_AUTHENTICATED);

    return !in_room || authenticated;
}

/*
 * P2:
 *
 * AG(AUTHENTICATED -> WS_OPEN)
 */
bool kripke_property_auth_requires_ws(
    client_state_t state)
{
    bool authenticated =
        kripke_has_ap(
            state,
            KRIPKE_AP_AUTHENTICATED);

    bool ws_open =
        kripke_has_ap(
            state,
            KRIPKE_AP_WS_OPEN);

    return !authenticated || ws_open;
}

bool kripke_properties_hold(
    client_state_t state)
{
    return kripke_property_room_requires_auth(state) &&
           kripke_property_auth_requires_ws(state);
}

/*
 * ============================================================
 * Bounded Model Checking
 * ============================================================
 */

#define KRIPKE_MAX_BOUND 32

typedef struct
{
    client_state_t states[KRIPKE_MAX_BOUND + 1];

    client_event_t events[KRIPKE_MAX_BOUND];
} kripke_trace_t;

/*
 * BMC deliberately uses ALL shared events.
 *
 * client_state_next() decides whether an edge actually belongs
 * to the transition relation R.
 */
static const client_event_t g_events[] = {
    CLIENT_EVENT_HTTP_UPGRADE_OK,

    CLIENT_EVENT_LOGIN_OK,
    CLIENT_EVENT_LOGIN_FAIL,

    CLIENT_EVENT_JOIN_OK,
    CLIENT_EVENT_JOIN_FAIL,

    CLIENT_EVENT_LEAVE_OK,
    CLIENT_EVENT_DISCONNECT};

#define EVENT_TOTAL \
    ((int)(sizeof(g_events) / sizeof(g_events[0])))

static void print_state(
    client_state_t state)
{
    uint32_t labels =
        kripke_label(state);

    printf(
        "%s { ws_open=%d, authenticated=%d, in_room=%d }",
        client_state_name(state),

        (labels & KRIPKE_AP_WS_OPEN)
            ? 1
            : 0,

        (labels & KRIPKE_AP_AUTHENTICATED)
            ? 1
            : 0,

        (labels & KRIPKE_AP_IN_ROOM)
            ? 1
            : 0);
}

static void print_trace(
    const kripke_trace_t *trace,
    int depth)
{
    printf(
        "\n"
        "========================================\n"
        "COUNTEREXAMPLE\n"
        "========================================\n");

    printf("S0: ");

    print_state(trace->states[0]);

    printf("\n");

    for (int i = 0; i < depth; ++i)
    {

        printf(
            "    --[%s]-->\n",
            client_event_name(
                trace->events[i]));

        printf(
            "S%d: ",
            i + 1);

        print_state(
            trace->states[i + 1]);

        printf("\n");
    }

    printf(
        "========================================\n");
}

static bool bmc_dfs(
    client_state_t current,
    int depth,
    int bound,
    kripke_trace_t *trace,
    bool print_counterexample)
{
    /*
     * Safety invariant is checked at every reachable state.
     */
    if (!kripke_properties_hold(current))
    {

        if (print_counterexample)
        {
            print_trace(
                trace,
                depth);
        }

        return false;
    }

    if (depth >= bound)
    {
        return true;
    }

    /*
     * Enumerate R(current, next).
     */
    for (int i = 0;
         i < EVENT_TOTAL;
         ++i)
    {

        client_event_t event =
            g_events[i];

        client_state_t next;

        /*
         * This is the important part:
         *
         * Kripke DOES NOT maintain another copy
         * of the transition rules.
         *
         * It calls the exact same state-machine
         * implementation used by client.c.
         */
        if (!client_state_next(
                current,
                event,
                &next))
        {

            /*
             * Illegal transition -> no edge in R.
             */
            continue;
        }

        trace->events[depth] =
            event;

        trace->states[depth + 1] =
            next;

        if (!bmc_dfs(
                next,
                depth + 1,
                bound,
                trace,
                print_counterexample))
        {

            return false;
        }
    }

    return true;
}

bool kripke_bmc(
    int bound,
    bool print_counterexample)
{
    if (bound < 0 ||
        bound > KRIPKE_MAX_BOUND)
    {

        printf(
            "[BMC ERROR] Bound must be between 0 and %d\n",
            KRIPKE_MAX_BOUND);

        return false;
    }

    kripke_trace_t trace;

    memset(
        &trace,
        0,
        sizeof(trace));

    trace.states[0] =
        client_state_initial();

    printf(
        "\nRunning bounded model checking...\n"
        "Initial state : %s\n"
        "Bound k       : %d\n",
        client_state_name(
            trace.states[0]),
        bound);

    bool result =
        bmc_dfs(
            trace.states[0],
            0,
            bound,
            &trace,
            print_counterexample);

    if (result)
    {

        printf(
            "[BMC PASS] "
            "No safety-property counterexample "
            "found up to k=%d\n",
            bound);
    }
    else
    {

        printf(
            "[BMC FAIL] "
            "Safety-property violation found.\n");
    }

    return result;
}

/*
 * ============================================================
 * Explicit tests
 * ============================================================
 */

static int tests_passed = 0;
static int tests_failed = 0;

static void expect_transition(
    const char *name,
    client_state_t current,
    client_event_t event,
    bool expected_allowed,
    client_state_t expected_state)
{
    client_state_t next;

    bool allowed =
        client_state_next(
            current,
            event,
            &next);

    bool ok =
        allowed == expected_allowed;

    if (expected_allowed)
    {
        ok =
            ok &&
            next == expected_state;
    }

    if (ok)
    {

        printf(
            "[PASS] %s\n",
            name);

        ++tests_passed;
    }
    else
    {

        printf(
            "[FAIL] %s\n"
            "       current  = %s\n"
            "       event    = %s\n"
            "       allowed  = %d\n"
            "       next     = %s\n",
            name,
            client_state_name(current),
            client_event_name(event),
            allowed ? 1 : 0,
            client_state_name(next));

        ++tests_failed;
    }
}

static void test_normal_flow(void)
{
    printf(
        "\n--- Normal connection flow ---\n");

    expect_transition(
        "HTTP handshake -> WebSocket",
        STATE_HTTP_HANDSHAKE,
        CLIENT_EVENT_HTTP_UPGRADE_OK,
        true,
        STATE_WS_CONNECTED);

    expect_transition(
        "Successful login -> authenticated",
        STATE_WS_CONNECTED,
        CLIENT_EVENT_LOGIN_OK,
        true,
        STATE_AUTHENTICATED);

    expect_transition(
        "Successful join -> in room",
        STATE_AUTHENTICATED,
        CLIENT_EVENT_JOIN_OK,
        true,
        STATE_IN_ROOM);

    expect_transition(
        "Leave room -> authenticated",
        STATE_IN_ROOM,
        CLIENT_EVENT_LEAVE_OK,
        true,
        STATE_AUTHENTICATED);
}

static void test_login_fail(void)
{
    printf(
        "\n--- Authentication failure ---\n");

    expect_transition(
        "Failed login remains WS_CONNECTED",
        STATE_WS_CONNECTED,
        CLIENT_EVENT_LOGIN_FAIL,
        true,
        STATE_WS_CONNECTED);
}

static void test_join_fail(void)
{
    printf(
        "\n--- Room failure ---\n");

    expect_transition(
        "Failed JOIN remains authenticated",
        STATE_AUTHENTICATED,
        CLIENT_EVENT_JOIN_FAIL,
        true,
        STATE_AUTHENTICATED);
}

static void test_forbidden_transitions(void)
{
    printf(
        "\n--- Forbidden transitions ---\n");

    expect_transition(
        "Cannot LOGIN before WebSocket handshake",
        STATE_HTTP_HANDSHAKE,
        CLIENT_EVENT_LOGIN_OK,
        false,
        STATE_HTTP_HANDSHAKE);

    expect_transition(
        "Cannot JOIN before LOGIN",
        STATE_WS_CONNECTED,
        CLIENT_EVENT_JOIN_OK,
        false,
        STATE_WS_CONNECTED);

    expect_transition(
        "Cannot send LOGIN_OK while already in room",
        STATE_IN_ROOM,
        CLIENT_EVENT_LOGIN_OK,
        false,
        STATE_IN_ROOM);
}

static void test_disconnect(void)
{
    printf(
        "\n--- Disconnect ---\n");

    expect_transition(
        "Disconnect authenticated client",
        STATE_AUTHENTICATED,
        CLIENT_EVENT_DISCONNECT,
        true,
        STATE_HTTP_HANDSHAKE);

    expect_transition(
        "Disconnect room client",
        STATE_IN_ROOM,
        CLIENT_EVENT_DISCONNECT,
        true,
        STATE_HTTP_HANDSHAKE);
}

static void test_properties(void)
{
    printf(
        "\n--- Kripke properties ---\n");

    client_state_t states[] = {
        STATE_HTTP_HANDSHAKE,
        STATE_WS_CONNECTED,
        STATE_AUTHENTICATED,
        STATE_IN_ROOM};

    int count =
        (int)(sizeof(states) /
              sizeof(states[0]));

    for (int i = 0;
         i < count;
         ++i)
    {

        if (kripke_properties_hold(
                states[i]))
        {

            printf(
                "[PASS] properties(%s)\n",
                client_state_name(
                    states[i]));

            ++tests_passed;
        }
        else
        {

            printf(
                "[FAIL] properties(%s)\n",
                client_state_name(
                    states[i]));

            ++tests_failed;
        }
    }
}

int kripke_run_tests(void)
{
    tests_passed = 0;
    tests_failed = 0;

    printf(
        "\n"
        "============================================\n"
        " CHAPTER 1 - STATE MACHINE / KRIPKE TESTS\n"
        "============================================\n");

    test_normal_flow();

    test_login_fail();

    test_join_fail();

    test_forbidden_transitions();

    test_disconnect();

    test_properties();

    printf(
        "\n"
        "============================================\n"
        " Passed : %d\n"
        " Failed : %d\n"
        "============================================\n",
        tests_passed,
        tests_failed);

    return tests_failed == 0
               ? 0
               : 1;
}
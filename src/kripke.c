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

    case STATE_IDLE:
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

    case STATE_CLOSED:
        return KRIPKE_AP_CLOSED;

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

bool kripke_property_closed_is_clean(client_state_t state)
{
    if (!kripke_has_ap(state, KRIPKE_AP_CLOSED)) return true;

    return !kripke_has_ap(state, KRIPKE_AP_WS_OPEN) &&
           !kripke_has_ap(state, KRIPKE_AP_AUTHENTICATED) &&
           !kripke_has_ap(state, KRIPKE_AP_IN_ROOM);
}

bool kripke_properties_hold(
    client_state_t state)
{
    return kripke_property_room_requires_auth(state) &&
           kripke_property_auth_requires_ws(state) &&
           kripke_property_closed_is_clean(state);
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
    CLIENT_EVENT_ACCEPT,
    CLIENT_EVENT_HTTP_UPGRADE_OK,

    CLIENT_EVENT_LOGIN_OK,
    CLIENT_EVENT_LOGIN_FAIL,

    CLIENT_EVENT_JOIN_OK,
    CLIENT_EVENT_JOIN_FAIL,

    CLIENT_EVENT_LEAVE_OK,
    CLIENT_EVENT_ROOM_CLOSED,
    CLIENT_EVENT_LOGOUT,
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
 * Liveness (EF reachability) and completeness threshold
 * ============================================================
 */

static bool reachable_from(
    client_state_t from,
    bool (*goal)(client_state_t))
{
    bool visited[STATE_CLOSED + 1];
    for (int i = 0; i <= STATE_CLOSED; ++i) visited[i] = false;

    client_state_t stack[64];
    int top = 0;
    stack[top++] = from;
    visited[from] = true;

    while (top > 0)
    {
        client_state_t s = stack[--top];
        if (goal(s)) return true;

        for (int i = 0; i < EVENT_TOTAL; ++i)
        {
            client_state_t nx;
            if (client_state_next(s, g_events[i], &nx) && !visited[nx])
            {
                visited[nx] = true;
                stack[top++] = nx;
            }
        }
    }
    return false;
}

static bool goal_room_or_closed(client_state_t s)
{
    return s == STATE_IN_ROOM || s == STATE_CLOSED;
}

static bool goal_authenticated(client_state_t s)
{
    return s == STATE_AUTHENTICATED;
}

bool kripke_liveness_holds(void)
{
    /* L1: every connected state can still reach IN_ROOM or CLOSED,
     *     i.e. it is never permanently stuck before progress. */
    for (client_state_t s = STATE_IDLE; s <= STATE_CLOSED; ++s)
    {
        if (!kripke_has_ap(s, KRIPKE_AP_WS_OPEN)) continue;
        if (!reachable_from(s, goal_room_or_closed)) return false;
    }

    /* L2: from IN_ROOM one can always get back to AUTHENTICATED (leave). */
    if (!reachable_from(STATE_IN_ROOM, goal_authenticated)) return false;

    return true;
}

int kripke_completeness_threshold(void)
{
    int dist[STATE_CLOSED + 1];
    for (int i = 0; i <= STATE_CLOSED; ++i) dist[i] = -1;

    client_state_t queue[64];
    int head = 0, tail = 0;

    client_state_t s0 = client_state_initial();
    dist[s0] = 0;
    queue[tail++] = s0;

    int max_dist = 0;
    while (head < tail)
    {
        client_state_t s = queue[head++];
        for (int i = 0; i < EVENT_TOTAL; ++i)
        {
            client_state_t nx;
            if (client_state_next(s, g_events[i], &nx) && dist[nx] < 0)
            {
                dist[nx] = dist[s] + 1;
                if (dist[nx] > max_dist) max_dist = dist[nx];
                queue[tail++] = nx;
            }
        }
    }
    return max_dist;
}

/*
 * Tier-2 / product model: two connections A, B of the SAME account.
 * State = (a_logged, b_logged). Invariant: not both logged.
 */
static bool session_invariant_ok(int a_logged, int b_logged)
{
    return !(a_logged && b_logged);
}

/* Explore the product (interleaving) BFS. Returns true if the invariant holds
 * on every reachable state; sets *violation when a bad state is reachable. */
static bool session_explore(bool buggy, int *viol_a, int *viol_b)
{
    bool visited[2][2] = { { false, false }, { false, false } };

    int qa[8], qb[8], head = 0, tail = 0;
    qa[tail] = 0; qb[tail] = 0; tail++;
    visited[0][0] = true;

    while (head < tail)
    {
        int a = qa[head], b = qb[head];
        head++;

        if (!session_invariant_ok(a, b))
        {
            if (viol_a) *viol_a = a;
            if (viol_b) *viol_b = b;
            return false;
        }

        int na[4], nb[4], cnt = 0;

        if (a == 0)   /* A_login */
        {
            if (buggy)         { na[cnt] = 1; nb[cnt] = b; cnt++; }
            else if (b == 0)   { na[cnt] = 1; nb[cnt] = 0; cnt++; }
            else               { na[cnt] = 0; nb[cnt] = 1; cnt++; }  /* rejected */
        }
        if (a == 1)   /* A_logout */
        {
            na[cnt] = 0; nb[cnt] = b; cnt++;
        }
        if (b == 0)   /* B_login */
        {
            if (buggy)         { na[cnt] = a; nb[cnt] = 1; cnt++; }
            else if (a == 0)   { na[cnt] = 0; nb[cnt] = 1; cnt++; }
            else               { na[cnt] = 1; nb[cnt] = 0; cnt++; }  /* rejected */
        }
        if (b == 1)   /* B_logout */
        {
            na[cnt] = a; nb[cnt] = 0; cnt++;
        }

        for (int i = 0; i < cnt; ++i)
        {
            if (!visited[na[i]][nb[i]])
            {
                visited[na[i]][nb[i]] = true;
                qa[tail] = na[i];
                qb[tail] = nb[i];
                tail++;
            }
        }
    }
    return true;
}

bool kripke_session_mutex_holds(void)
{
    return session_explore(false, NULL, NULL);
}

bool kripke_session_mutex_buggy(void)
{
    int a = 0, b = 0;
    bool ok = session_explore(true, &a, &b);
    if (!ok)
    {
        printf("[SESSION] counterexample: (A_logged=%d, B_logged=%d) "
               "-> both sessions active\n", a, b);
    }
    return !ok;
}

/*
 * ============================================================
 * Tier-3 model: room product (two connection roles + shared room)
 * ============================================================
 *
 * Tier-1 models ONE connection; Tier-2 models two connections that only
 * touch the session table. Neither can see the room, because the room is
 * SHARED data: a single admin event moves every member at once.
 *
 * Global state = (a, b, a_in_room, b_in_room, members)
 *   a, b      : STATE_* of the two connection roles
 *   a_in_room : mirrors client->room[0] != '\0'   (shared room data)
 *   b_in_room : mirrors client->room[0] != '\0'
 *   members   : mirrors room->num_clients
 *
 * State space = 6 * 6 * 2 * 2 * 3 = 216 states.
 *
 * Why only two roles: the invariants below compare a member against
 * "somebody else", so one member plus one other is the minimum that can
 * express them at all. The real MAX_CLIENTS_PER_ROOM is deliberately not
 * modelled here - it is enforced structurally by clients[MAX_CLIENTS_PER_ROOM]
 * together with the guard in room_join_commit(), which the array bound already
 * guarantees. What the model adds is the part an array cannot protect:
 * the agreement between the shared room data and each connection's own
 * state machine.
 *
 * Invariants, checked on every reachable state:
 *
 *   I1 (P5)  the room reference and the state machine agree:
 *              in_room[i]  <->  state[i] == STATE_IN_ROOM
 *            A violation means a STRANDED client: JOIN requires
 *            STATE_AUTHENTICATED and client_leave_room() returns early on
 *            an empty room name, so it can never rejoin and never leave.
 *
 *   I2 (P10) room->num_clients equals the real member count:
 *              members == (a_in_room ? 1 : 0) + (b_in_room ? 1 : 0)
 *
 *   I3       capacity: members <= 2 (structural with two roles)
 *
 * Transitions:
 *   - local, asynchronous interleaving: one role takes one event that
 *     client_state_next() accepts. CLIENT_EVENT_ROOM_CLOSED is NOT a local
 *     event, because in the code it is only ever produced by room_delete().
 *   - shared: DELETE_ROOM, the console admin deleting the room. It moves
 *     EVERY member to STATE_AUTHENTICATED in one step and zeroes members -
 *     exactly the event a single-client model cannot express.
 */

#define ROOM_ROLES      2
#define ROOM_SYS_STATES (6 * 6 * 2 * 2 * 3)

typedef struct
{
    client_state_t a;
    client_state_t b;
    bool          a_in_room;
    bool          b_in_room;
    int           members;
} room_sys_t;

static int room_sys_index(const room_sys_t *s)
{
    return (((((int)s->a * 6 + (int)s->b) * 2
              + (s->a_in_room ? 1 : 0)) * 2
              + (s->b_in_room ? 1 : 0)) * 3
              + s->members);
}

static void room_sys_decode(int idx, room_sys_t *s)
{
    int t = idx;
    s->members    = t % 3;               t /= 3;
    s->b_in_room  = (t % 2) != 0;        t /= 2;
    s->a_in_room  = (t % 2) != 0;        t /= 2;
    s->b          = (client_state_t)(t % 6); t /= 6;
    s->a          = (client_state_t)(t % 6);
}

static void room_sys_print(const room_sys_t *s)
{
    printf("A=%-16s B=%-16s inRoom=(%d,%d) members=%d\n",
           client_state_name(s->a), client_state_name(s->b),
           s->a_in_room ? 1 : 0, s->b_in_room ? 1 : 0, s->members);
}

static bool room_invariant_ok(const room_sys_t *s, const char **why)
{
    if (s->a_in_room != (s->a == STATE_IN_ROOM) ||
        s->b_in_room != (s->b == STATE_IN_ROOM))
    {
        if (why) *why = "I1 stranded client: room reference and state "
                        "machine disagree";
        return false;
    }
    int expect = (s->a_in_room ? 1 : 0) + (s->b_in_room ? 1 : 0);
    if (s->members != expect)
    {
        if (why) *why = "I2 num_clients does not match the real member count";
        return false;
    }
    if (s->members > ROOM_ROLES)
    {
        if (why) *why = "I3 room capacity exceeded";
        return false;
    }
    return true;
}

static bool         g_room_visited[ROOM_SYS_STATES];
static int          g_room_pred[ROOM_SYS_STATES];
static char         g_room_pred_ev[ROOM_SYS_STATES][24];
static room_sys_t   g_room_queue[ROOM_SYS_STATES];

static void room_push(const room_sys_t *s, int from, const char *ev, int *tail)
{
    int idx = room_sys_index(s);
    if (idx < 0 || idx >= ROOM_SYS_STATES) return;
    if (g_room_visited[idx]) return;
    g_room_visited[idx] = true;
    g_room_pred[idx] = from;
    snprintf(g_room_pred_ev[idx], sizeof g_room_pred_ev[idx], "%s", ev);
    g_room_queue[(*tail)++] = *s;
}

static bool room_product_explore(room_bug_t bug, room_sys_t *bad, const char **why)
{
    memset(g_room_visited, 0, sizeof g_room_visited);
    for (int i = 0; i < ROOM_SYS_STATES; ++i)
    {
        g_room_pred[i] = -1;
        g_room_pred_ev[i][0] = '\0';
    }

    int head = 0, tail = 0;
    room_sys_t s0;
    s0.a = STATE_HTTP_HANDSHAKE;
    s0.b = STATE_HTTP_HANDSHAKE;
    s0.a_in_room = false;
    s0.b_in_room = false;
    s0.members = 0;
    g_room_visited[room_sys_index(&s0)] = true;
    g_room_queue[tail++] = s0;

    while (head < tail)
    {
        room_sys_t cur = g_room_queue[head++];
        int cur_idx = room_sys_index(&cur);

        const char *reason = NULL;
        if (!room_invariant_ok(&cur, &reason))
        {
            if (bad) *bad = cur;
            if (why) *why = reason;

            /* Reconstruct the shortest path that reaches the bad state. */
            int chain[ROOM_SYS_STATES];
            int n = 0;
            int idx = cur_idx;
            while (idx >= 0 && n < ROOM_SYS_STATES)
            {
                chain[n++] = idx;
                idx = g_room_pred[idx];
            }
            printf("      counterexample path (%d steps):\n", n - 1);
            room_sys_t st;
            /* chain[] runs backwards, so chain[n-1] is the initial state
             * and pred_ev[v] is the event that reaches v from its parent. */
            room_sys_decode(chain[n - 1], &st);
            printf("      %-22s", "(initial)");
            room_sys_print(&st);
            for (int i = n - 2; i >= 0; --i)
            {
                room_sys_decode(chain[i], &st);
                printf("      %-22s", g_room_pred_ev[chain[i]]);
                room_sys_print(&st);
            }
            return false;
        }

        /* Local interleaving: one role takes one legal event. */
        for (int role = 0; role < 2; ++role)
        {
            for (int e = 0; e < CLIENT_EVENT_COUNT; ++e)
            {
                /* ROOM_CLOSED only ever comes from room_delete(), which is
                 * modelled as the shared DELETE_ROOM step below. */
                if (e == CLIENT_EVENT_ROOM_CLOSED) continue;

                client_state_t base = role == 0 ? cur.a : cur.b;
                bool was_in = role == 0 ? cur.a_in_room : cur.b_in_room;
                client_state_t next;
                if (!client_state_next(base, (client_event_t)e, &next)) continue;

                room_sys_t nxt = cur;
                if (role == 0) nxt.a = next; else nxt.b = next;

                /* Mirror what the code does to the shared room data. */
                if (e == CLIENT_EVENT_JOIN_OK)
                {
                    if (role == 0) nxt.a_in_room = true; else nxt.b_in_room = true;
                    nxt.members = cur.members + 1;
                }
                else if (e == CLIENT_EVENT_LEAVE_OK)
                {
                    if (role == 0) nxt.a_in_room = false; else nxt.b_in_room = false;
                    nxt.members = cur.members - 1;
                }
                else if (e == CLIENT_EVENT_DISCONNECT)
                {
                    if (was_in)
                    {
                        if (role == 0) nxt.a_in_room = false; else nxt.b_in_room = false;
                        nxt.members = cur.members - 1;
                    }
                }

                char label[24];
                snprintf(label, sizeof label, "%s.%s",
                         role == 0 ? "A" : "B", client_event_name((client_event_t)e));
                room_push(&nxt, cur_idx, label, &tail);
            }
        }

        /* Shared event: the console admin deletes the room. */
        {
            room_sys_t nxt = cur;

            if (bug == ROOM_BUG_STRANDED_FLAG)
            {
                /* Models clearing c->room while the transition into
                 * STATE_AUTHENTICATED never happened: the client keeps
                 * STATE_IN_ROOM with no room. */
                nxt.a_in_room = false;
                nxt.b_in_room = false;
                nxt.members = 0;
            }
            else if (bug == ROOM_BUG_PARTIAL_EVICT)
            {
                /* Models an evict loop that stops after the first member. */
                if (nxt.a == STATE_IN_ROOM) { nxt.a = STATE_AUTHENTICATED; nxt.a_in_room = false; }
                else if (nxt.b == STATE_IN_ROOM) { nxt.b = STATE_AUTHENTICATED; nxt.b_in_room = false; }
                nxt.members = 0;
            }
            else if (bug == ROOM_BUG_COUNT_NOT_RESET)
            {
                /* Models forgetting r->num_clients = 0. */
                if (nxt.a == STATE_IN_ROOM) { nxt.a = STATE_AUTHENTICATED; nxt.a_in_room = false; }
                if (nxt.b == STATE_IN_ROOM) { nxt.b = STATE_AUTHENTICATED; nxt.b_in_room = false; }
            }
            else
            {
                /* room_delete(): evict every member, then r->num_clients = 0. */
                if (nxt.a == STATE_IN_ROOM) { nxt.a = STATE_AUTHENTICATED; nxt.a_in_room = false; }
                if (nxt.b == STATE_IN_ROOM) { nxt.b = STATE_AUTHENTICATED; nxt.b_in_room = false; }
                nxt.members = 0;
            }

            /* A delete of an empty room changes nothing meaningful, but the
             * code still performs it, so the step stays enabled. */
            room_push(&nxt, cur_idx, "DELETE_ROOM", &tail);
        }
    }

    if (why) *why = NULL;
    return true;
}

bool kripke_room_product_holds(void)
{
    return room_product_explore(ROOM_BUG_NONE, NULL, NULL);
}

bool kripke_room_product_counterexample(room_bug_t bug)
{
    room_sys_t bad;
    const char *why = NULL;
    bool ok = room_product_explore(bug, &bad, &why);
    if (!ok)
    {
        printf("      violated: %s\n", why ? why : "(unknown)");
        printf("      bad state:  ");
        room_sys_print(&bad);
    }
    return !ok;
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
        "Accept -> HTTP handshake",
        STATE_IDLE,
        CLIENT_EVENT_ACCEPT,
        true,
        STATE_HTTP_HANDSHAKE);

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

    expect_transition(
        "Room closed -> authenticated",
        STATE_IN_ROOM,
        CLIENT_EVENT_ROOM_CLOSED,
        true,
        STATE_AUTHENTICATED);

    expect_transition(
        "Logout -> WebSocket (still connected)",
        STATE_AUTHENTICATED,
        CLIENT_EVENT_LOGOUT,
        true,
        STATE_WS_CONNECTED);
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
        "Must LEAVE before joining another room",
        STATE_IN_ROOM,
        CLIENT_EVENT_JOIN_OK,
        false,
        STATE_IN_ROOM);

    expect_transition(
        "Cannot send LOGIN_OK while already in room",
        STATE_IN_ROOM,
        CLIENT_EVENT_LOGIN_OK,
        false,
        STATE_IN_ROOM);

    expect_transition(
        "CLOSED is terminal (no outgoing edges)",
        STATE_CLOSED,
        CLIENT_EVENT_LOGIN_OK,
        false,
        STATE_CLOSED);
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
        STATE_CLOSED);

    expect_transition(
        "Disconnect room client",
        STATE_IN_ROOM,
        CLIENT_EVENT_DISCONNECT,
        true,
        STATE_CLOSED);
}

static void test_properties(void)
{
    printf(
        "\n--- Kripke properties ---\n");

    client_state_t states[] = {
        STATE_IDLE,
        STATE_HTTP_HANDSHAKE,
        STATE_WS_CONNECTED,
        STATE_AUTHENTICATED,
        STATE_IN_ROOM,
        STATE_CLOSED};

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

static void test_liveness(void)
{
    printf(
        "\n--- Liveness (EF reachability) ---\n");

    if (kripke_liveness_holds())
    {
        printf("[PASS] progress reachable from every connected state\n");
        ++tests_passed;
    }
    else
    {
        printf("[FAIL] liveness\n");
        ++tests_failed;
    }

    printf("[INFO] completeness threshold k* = %d\n",
           kripke_completeness_threshold());
}

static void test_session_mutex(void)
{
    printf(
        "\n--- Tier-2: single session (product A x B) ---\n");

    if (kripke_session_mutex_holds())
    {
        printf("[PASS] AG(!(session_A & session_B)) holds\n");
        ++tests_passed;
    }
    else
    {
        printf("[FAIL] mutual exclusion violated by the model\n");
        ++tests_failed;
    }

    if (kripke_session_mutex_buggy())
    {
        printf("[PASS] buggy variant: counterexample found (as expected)\n");
        ++tests_passed;
    }
    else
    {
        printf("[FAIL] buggy variant: no counterexample (unexpected)\n");
        ++tests_failed;
    }
}

static void test_room_product(void)
{
    printf(
        "\n--- Tier-3: room product (2 roles + shared room, 216 states) ---\n");

    if (kripke_room_product_holds())
    {
        printf("[PASS] I1/I2/I3 hold on every reachable state\n");
        printf("       I1 room ref and state machine agree (no stranded client)\n");
        printf("       I2 num_clients matches the real member count\n");
        printf("       I3 room capacity respected\n");
        ++tests_passed;
    }
    else
    {
        printf("[FAIL] a room invariant is violated by the model\n");
        ++tests_failed;
    }

    struct { room_bug_t bug; const char *label; } variants[] = {
        { ROOM_BUG_STRANDED_FLAG,  "clears room ref, keeps STATE_IN_ROOM" },
        { ROOM_BUG_PARTIAL_EVICT,  "evict loop stops at first member" },
        { ROOM_BUG_COUNT_NOT_RESET, "forgets num_clients = 0" }
    };
    for (size_t i = 0; i < sizeof variants / sizeof variants[0]; ++i)
    {
        if (kripke_room_product_counterexample(variants[i].bug))
        {
            printf("[PASS] buggy variant caught: %s\n", variants[i].label);
            ++tests_passed;
        }
        else
        {
            printf("[FAIL] buggy variant NOT caught: %s\n", variants[i].label);
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

    test_liveness();

    test_session_mutex();

    test_room_product();

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
#include "kripke.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    int bound = 8;

    if (argc >= 2)
    {

        bound = atoi(argv[1]);

        if (bound < 0)
        {
            bound = 0;
        }
    }

    printf(
        "=====================================================\n"
        " CHAPTER 1 - KRIPKE STRUCTURE / BMC\n"
        " WebSocket Chat Connection State Verification\n"
        "=====================================================\n");

    printf(
        "\n"
        "Shared runtime state machine:\n"
        "\n"
        " STATE_IDLE\n"
        "          | ACCEPT\n"
        "          v\n"
        " STATE_HTTP_HANDSHAKE\n"
        "          | HTTP_UPGRADE_OK\n"
        "          v\n"
        " STATE_WS_CONNECTED\n"
        "          | LOGIN_OK\n"
        "          v\n"
        " STATE_AUTHENTICATED\n"
        "          | JOIN_OK\n"
        "          v\n"
        " STATE_IN_ROOM\n"
        "          | LEAVE_OK / ROOM_CLOSED\n"
        "          v\n"
        " STATE_AUTHENTICATED\n"
        "\n"
        " (switch rooms: LEAVE then JOIN - JOIN is only valid from\n"
        "  AUTHENTICATED, i.e. a client must leave before joining another)\n"
        " (single session: a 2nd LOGIN for the same account fails -> LOGIN_FAIL,\n"
        "  the connection stays in WS_CONNECTED)\n"
        "\n"
        " (any live state) --DISCONNECT--> STATE_CLOSED  (terminal)\n");

    printf(
        "\n"
        "Kripke model:\n"
        "\n"
        " K = (S, S0, R, L)\n"
        "\n"
        " S  = 6 connection states (IDLE..CLOSED)\n"
        " S0 = STATE_IDLE\n"
        " R  = client_state_next()\n"
        " L  = {WS_OPEN, AUTHENTICATED, IN_ROOM, CLOSED}\n");

    printf(
        "\n"
        "Safety properties:\n"
        "\n"
        " P1: AG(IN_ROOM -> AUTHENTICATED)\n"
        " P2: AG(AUTHENTICATED -> WS_OPEN)\n"
        " P3: AG(CLOSED -> !(WS_OPEN | AUTHENTICATED | IN_ROOM))\n"
        "\n"
        "Liveness (EF reachability):\n"
        "\n"
        " L1: from every connected state, IN_ROOM or CLOSED is reachable\n"
        " L2: from IN_ROOM, AUTHENTICATED is reachable (leave possible)\n");

    if (kripke_run_tests() != 0)
    {

        printf(
            "\n"
            "CHAPTER 1 RESULT: TEST FAILURE\n");

        return EXIT_FAILURE;
    }

    if (!kripke_bmc(
            bound,
            true))
    {

        printf(
            "\n"
            "CHAPTER 1 RESULT: MODEL CHECK FAILED\n");

        return EXIT_FAILURE;
    }

    printf(
        "\n"
        "=====================================================\n"
        " CHAPTER 1 RESULT: VERIFIED\n"
        " Shared state machine verified up to bound k=%d\n"
        " (completeness threshold k* = %d)\n"
        "=====================================================\n",
        bound,
        kripke_completeness_threshold());

    return EXIT_SUCCESS;
}
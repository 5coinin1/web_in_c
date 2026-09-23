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
        " STATE_HTTP_HANDSHAKE\n"
        "          |\n"
        "          | HTTP_UPGRADE_OK\n"
        "          v\n"
        " STATE_WS_CONNECTED\n"
        "          |\n"
        "          | LOGIN_OK\n"
        "          v\n"
        " STATE_AUTHENTICATED\n"
        "          |\n"
        "          | JOIN_OK\n"
        "          v\n"
        " STATE_IN_ROOM\n"
        "          |\n"
        "          | LEAVE\n"
        "          v\n"
        " STATE_AUTHENTICATED\n");

    printf(
        "\n"
        "Kripke model:\n"
        "\n"
        " K = (S, S0, R, L)\n"
        "\n"
        " S  = connection states\n"
        " S0 = STATE_HTTP_HANDSHAKE\n"
        " R  = client_state_next()\n"
        " L  = {WS_OPEN, AUTHENTICATED, IN_ROOM}\n");

    printf(
        "\n"
        "Safety properties:\n"
        "\n"
        " P1: AG(IN_ROOM -> AUTHENTICATED)\n"
        " P2: AG(AUTHENTICATED -> WS_OPEN)\n");

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
        "=====================================================\n",
        bound);

    return EXIT_SUCCESS;
}
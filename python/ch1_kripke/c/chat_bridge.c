/* Test adapter only. Production files are compiled unchanged. */
#include "state_machine.h"
#include <stdio.h>
#include <string.h>

static bool next_state(client_state_t *s, client_event_t e, bool mutant) {
    if (mutant && *s == STATE_WS_CONNECTED && e == CLIENT_EVENT_JOIN_OK) {
        *s = STATE_IN_ROOM;
        return true;
    }
    return client_state_apply(s, e);
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--export")) {
        printf("{\"initial\":\"%s\",\"states\":[", client_state_name(client_state_initial()));
        for (int s=STATE_IDLE; s<=STATE_CLOSED; ++s)
            printf("%s\"%s\"", s==STATE_IDLE ? "" : ",", client_state_name((client_state_t)s));
        printf("],\"events\":[");
        for (int e=0; e<CLIENT_EVENT_COUNT; ++e)
            printf("%s\"%s\"", e ? "," : "", client_event_name((client_event_t)e));
        printf("],\"matrix\":[");
        int first=1;
        for (int s=STATE_IDLE; s<=STATE_CLOSED; ++s) {
            for (int e=0; e<CLIENT_EVENT_COUNT; ++e) {
                client_state_t target=(client_state_t)s;
                bool ok=client_state_apply(&target, (client_event_t)e);
                printf("%s{\"from\":\"%s\",\"event\":\"%s\",\"accepted\":%s,\"to\":\"%s\"}",
                       first ? "" : ",", client_state_name((client_state_t)s),
                       client_event_name((client_event_t)e), ok ? "true":"false", client_state_name(target));
                first=0;
            }
        }
        puts("]}");
        return 0;
    }
    bool mutant=argc>1 && !strcmp(argv[1], "--buggy-join");
    int start=mutant ? 2 : 1;
    client_state_t state=client_state_initial();
    bool auth=false;
    printf("{\"initial\":\"%s\",\"steps\":[", client_state_name(state));
    for (int i=start; i<argc; ++i) {
        int event;
        for (event=0; event<CLIENT_EVENT_COUNT; ++event)
            if (!strcmp(argv[i], client_event_name((client_event_t)event))) break;
        if (event==CLIENT_EVENT_COUNT) {
            puts("],\"error\":\"unknown event\"}");
            return 2;
        }
        bool ok=next_state(&state,(client_event_t)event,mutant);
        if (ok && event==CLIENT_EVENT_LOGIN_OK) auth=true;
        if (ok && (event==CLIENT_EVENT_LOGOUT || event==CLIENT_EVENT_DISCONNECT)) auth=false;
        printf("%s{\"event\":\"%s\",\"accepted\":%s,\"state\":\"%s\",\"auth_history\":%s}",
               i==start?"":",",client_event_name((client_event_t)event),ok?"true":"false",
               client_state_name(state),auth?"true":"false");
        if (!ok) {
            printf("],\"final\":\"%s\",\"violation\":false}\n",client_state_name(state));
            return 2;
        }
        if (state==STATE_IN_ROOM && !auth) {
            printf("],\"final\":\"%s\",\"violation\":true}\n",client_state_name(state));
            return 1;
        }
    }
    printf("],\"final\":\"%s\",\"violation\":false}\n",client_state_name(state));
    return 0;
}

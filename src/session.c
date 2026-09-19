#include "session.h"
#include <pthread.h>

static char g_sessions[MAX_SESSIONS][MAX_NICKNAME];
static int  g_session_count = 0;
static pthread_mutex_t g_session_lock = PTHREAD_MUTEX_INITIALIZER;

bool session_add(const char *username) {
    if (!username || !username[0]) return false;
    bool ok = false;
    pthread_mutex_lock(&g_session_lock);
    bool exists = false;
    for (int i = 0; i < g_session_count; i++) {
        if (strcmp(g_sessions[i], username) == 0) { exists = true; break; }
    }
    if (!exists && g_session_count < MAX_SESSIONS) {
        strncpy(g_sessions[g_session_count], username, MAX_NICKNAME - 1);
        g_sessions[g_session_count][MAX_NICKNAME - 1] = '\0';
        g_session_count++;
        ok = true;
    }
    pthread_mutex_unlock(&g_session_lock);
    return ok;
}

void session_remove(const char *username) {
    if (!username) return;
    pthread_mutex_lock(&g_session_lock);
    for (int i = 0; i < g_session_count; i++) {
        if (strcmp(g_sessions[i], username) == 0) {
            for (int j = i; j < g_session_count - 1; j++) {
                strcpy(g_sessions[j], g_sessions[j + 1]);
            }
            g_session_count--;
            break;
        }
    }
    pthread_mutex_unlock(&g_session_lock);
}

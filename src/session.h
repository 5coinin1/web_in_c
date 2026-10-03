#ifndef SESSION_H
#define SESSION_H

#include "common.h"

// Registry of currently logged-in usernames. Enforces that a single account has
// at most one active session at a time.

#define MAX_SESSIONS 256

typedef enum {
    SESSION_OK = 0,   // session acquired
    SESSION_DUP,      // the account already has an active session
    SESSION_FULL      // the session table is full
} session_result_t;

// Try to register an active session for username.
session_result_t session_add(const char *username);

// Remove the active session for username (no-op if absent).
void session_remove(const char *username);

#endif

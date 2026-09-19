#ifndef SESSION_H
#define SESSION_H

#include "common.h"

// Registry of currently logged-in usernames. Used to enforce that a single
// account has at most one active session at a time, so a room never shows two
// identical users.

#define MAX_SESSIONS 256

// Register an active session for username.
// Returns true if added, false if the account already has an active session.
bool session_add(const char *username);

// Remove the active session for username (no-op if absent).
void session_remove(const char *username);

#endif

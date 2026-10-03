#ifndef AUTH_H
#define AUTH_H

#include "common.h"

// Result codes for registration
typedef enum {
    AUTH_REG_OK = 0,      // registered successfully
    AUTH_REG_EXISTS,      // username already taken
    AUTH_REG_INVALID,     // bad username/password
    AUTH_REG_IO           // could not persist the account store
} auth_reg_result_t;

// Result codes for login
typedef enum {
    AUTH_OK = 0,          // credentials valid
    AUTH_BAD,             // wrong username or password
    AUTH_LOCKED           // too many failed attempts, temporarily locked
} auth_result_t;

// Server-side account store.
//
// Accounts are persisted in a compact binary file (magic "WSAC"), NOT plain
// text and NOT an SQLite database. Passwords are never stored in the clear:
// each account keeps a random 16-byte salt and a SHA-256(salt || password) hash.
#define SERVER_DATA_DIR "server_data"

// Load accounts from the binary store under data_dir (creates the directory
// and seeds default accounts if the store is missing/empty).
void auth_init(const char *data_dir);

// Verify credentials with a small per-username lockout after repeated failures.
auth_result_t auth_check(const char *username, const char *password);

// Register a new user. Persists to the binary store on success.
auth_reg_result_t auth_register(const char *username, const char *password);

// Parse an account store from a memory buffer (used for analysis/fuzzing).
// Returns 0 on success, -1 on a bad header. A build with -DVULN omits the
// bounds checks on purpose (see README).
int auth_store_parse(const uint8_t *buf, size_t len);

// Number of accounts currently loaded.
int auth_num_accounts(void);

#endif

#include "auth.h"
#include "bytes.h"
#include "path_util.h"
#include <ctype.h>
#include <time.h>
#include <pthread.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#define MAX_ACCOUNTS  256
#define USERNAME_MAX  31
#define MIN_USERNAME  3
#define MIN_PASSWORD  4
#define SALT_LEN      16
#define HASH_LEN      32
#define RECORD_SIZE   (32 + SALT_LEN + HASH_LEN + 8)  // 88 bytes

#define ACC_MAGIC     "WSAC"
#define ACC_VERSION   1          /* v1: SHA-256(salt || password) */

typedef struct {
    char    username[32];
    uint8_t salt[SALT_LEN];
    uint8_t hash[HASH_LEN];
    int64_t created_at;
} account_t;

static account_t g_accounts[MAX_ACCOUNTS];
static int       g_num_accounts = 0;
static char      g_db_path[256] = "server_data/accounts.dat";

// ---- brute-force lockout (per username) ----
#define MAX_LOGIN_FAILS 5
#define LOCKOUT_SECONDS 30
#define MAX_GUARDS      128

typedef struct {
    char   username[32];
    int    fails;
    time_t locked_until;
} login_guard_t;

static login_guard_t   g_guards[MAX_GUARDS];
static int             g_num_guards = 0;
static pthread_mutex_t g_guard_lock = PTHREAD_MUTEX_INITIALIZER;

// Caller must hold g_guard_lock.
static login_guard_t *guard_for(const char *username) {
    for (int i = 0; i < g_num_guards; i++) {
        if (strcmp(g_guards[i].username, username) == 0) return &g_guards[i];
    }
    if (g_num_guards >= MAX_GUARDS) return &g_guards[0];   // evict first (simple)
    login_guard_t *g = &g_guards[g_num_guards++];
    memset(g, 0, sizeof(*g));
    strncpy(g->username, username, sizeof(g->username) - 1);
    return g;
}

// Password hash: SHA-256(salt || password) with a per-account salt.
static void hash_password(const uint8_t *salt, const char *password,
                          uint8_t out[HASH_LEN]) {
    uint8_t buf[SALT_LEN + 128];
    size_t plen = strlen(password);
    if (plen > 128) plen = 128;
    memcpy(buf, salt, SALT_LEN);
    memcpy(buf + SALT_LEN, password, plen);
    SHA256(buf, SALT_LEN + plen, out);
}

static int find_account(const char *username) {
    for (int i = 0; i < g_num_accounts; i++) {
        if (strcmp(g_accounts[i].username, username) == 0) return i;
    }
    return -1;
}

static bool valid_username(const char *u) {
    size_t len = strlen(u);
    if (len < MIN_USERNAME || len > USERNAME_MAX) return false;
    for (size_t i = 0; i < len; i++) {
        if (!isalnum((unsigned char)u[i]) && u[i] != '_') return false;
    }
    return true;
}

static bool valid_password(const char *p) {
    size_t len = strlen(p);
    if (len < MIN_PASSWORD || len > 63) return false;
    for (size_t i = 0; i < len; i++) {
        if (isspace((unsigned char)p[i])) return false;
    }
    return true;
}

// ---- binary store I/O ----

// Parse an account store from a memory buffer.
//
// This is the single parser targeted by the analysis modules:
//   Ch2 (memory safety) - bounds / overflow bugs
//   Ch3 (SMT)           - the off = 12 + i*RECORD_SIZE / count arithmetic
//   Ch4 (fuzzing)       - the "WSAC" magic + count + records layout
//
// A clean build performs every bounds check. Compiling with -DVULN removes
// them on purpose; the injected bugs are marked [BUG x] below.
int auth_store_parse(const uint8_t *buf, size_t len) {
    g_num_accounts = 0;

#ifdef VULN
    // [BUG C - CWE-193 off-by-one] Header length check is one short: an
    // 11-byte buffer is accepted and get_u32() then reads buf[8..11], one
    // byte past the end. The fixed bound is len < 12.
    if (!buf || len < 11) return -1;
#else
    if (!buf || len < 12) return -1;
#endif

    if (memcmp(buf, ACC_MAGIC, 4) != 0) return -1;
    if (get_u16(buf + 4) != ACC_VERSION) return -1;

    uint32_t count = get_u32(buf + 8);
#ifndef VULN
    // [FIX A - CWE-129] Bound the file-controlled count before it indexes the
    // fixed g_accounts[] array.
    if (count > MAX_ACCOUNTS) count = MAX_ACCOUNTS;
#endif

    for (uint32_t i = 0; i < count; i++) {
        size_t off = 12 + (size_t)i * RECORD_SIZE;

#ifndef VULN
        // [FIX B - CWE-125/190] Overflow-safe bounds check. Uses subtraction,
        // not "off + RECORD_SIZE <= len", so it cannot wrap around.
        if (off > len || RECORD_SIZE > len - off) break;
#endif
        // [BUG A - CWE-787] With -DVULN, count is unbounded, so g_num_accounts
        // can pass MAX_ACCOUNTS and the store below writes past g_accounts[].
        // [BUG B - CWE-125] With -DVULN, off is unchecked, so these reads can
        // go past the end of buf.
        account_t *a = &g_accounts[g_num_accounts];
        memcpy(a->username, buf + off, 32);
        a->username[31] = '\0';
        memcpy(a->salt, buf + off + 32, SALT_LEN);
        memcpy(a->hash, buf + off + 32 + SALT_LEN, HASH_LEN);
        a->created_at = get_i64(buf + off + 32 + SALT_LEN + HASH_LEN);
        g_num_accounts++;
    }
    return 0;
}

static int load_store(void) {
    FILE *f = fopen(g_db_path, "rb");
    if (!f) return -1;

    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);

    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    int rc = auth_store_parse(buf, rd);
    free(buf);
    fclose(f);
    return rc;
}

static bool save_store(void) {
    char tmp[300];
    FILE *f = atomic_open(g_db_path, tmp, sizeof(tmp));
    if (!f) {
        LOG_ERR("Cannot write account store '%s'", g_db_path);
        return false;
    }

    uint8_t header[12];
    memcpy(header, ACC_MAGIC, 4);
    put_u16(header + 4, ACC_VERSION);
    put_u16(header + 6, 0);
    put_u32(header + 8, (uint32_t)g_num_accounts);
    fwrite(header, 1, sizeof(header), f);

    for (int i = 0; i < g_num_accounts; i++) {
        uint8_t rec[RECORD_SIZE];
        memset(rec, 0, sizeof(rec));
        memcpy(rec, g_accounts[i].username, strlen(g_accounts[i].username));
        memcpy(rec + 32, g_accounts[i].salt, SALT_LEN);
        memcpy(rec + 32 + SALT_LEN, g_accounts[i].hash, HASH_LEN);
        put_i64(rec + 32 + SALT_LEN + HASH_LEN, g_accounts[i].created_at);
        fwrite(rec, 1, sizeof(rec), f);
    }

    if (ferror(f) != 0) { atomic_abort(tmp, f); return false; }
    if (atomic_commit(g_db_path, tmp, f) != 0) {
        LOG_ERR("Atomic save of account store '%s' failed", g_db_path);
        return false;
    }
    return true;
}

static void add_account(const char *username, const char *password) {
    if (g_num_accounts >= MAX_ACCOUNTS) return;
    account_t *a = &g_accounts[g_num_accounts++];
    memset(a, 0, sizeof(*a));
    strncpy(a->username, username, USERNAME_MAX);
    RAND_bytes(a->salt, SALT_LEN);
    hash_password(a->salt, password, a->hash);
    a->created_at = (int64_t)time(NULL);
}

void auth_init(const char *data_dir) {
    if (data_dir && data_dir[0]) {
        snprintf(g_db_path, sizeof(g_db_path), "%s/accounts.dat", data_dir);
        ensure_dir(data_dir);
    }
    g_num_accounts = 0;

    if (load_store() == 0 && g_num_accounts > 0) {
        LOG_INFO("Loaded %d account(s) from '%s'", g_num_accounts, g_db_path);
        return;
    }

    // Seed default accounts (stored as salted hashes, never plaintext)
    add_account("alice", "secret123");
    add_account("bob", "hunter2");
    save_store();
    LOG_INFO("Seeded %d default account(s) into '%s'", g_num_accounts, g_db_path);
}

auth_result_t auth_check(const char *username, const char *password) {
    if (!username || !password) return AUTH_BAD;

    // Reject early if this username is currently locked out.
    pthread_mutex_lock(&g_guard_lock);
    login_guard_t *guard = guard_for(username);
    time_t now = time(NULL);
    bool locked = (guard->locked_until > now);
    pthread_mutex_unlock(&g_guard_lock);
    if (locked) return AUTH_LOCKED;

    // Verify. For an unknown user we still hash (with a dummy salt) so the
    // response time does not reveal whether the account exists.
    bool ok = false;
    uint8_t computed[HASH_LEN];
    int idx = find_account(username);
    if (idx >= 0) {
        hash_password(g_accounts[idx].salt, password, computed);
        ok = CRYPTO_memcmp(computed, g_accounts[idx].hash, HASH_LEN) == 0;
    } else {
        uint8_t dummy_salt[SALT_LEN] = {0};
        hash_password(dummy_salt, password, computed);
    }

    // Update the failure counter / lockout.
    pthread_mutex_lock(&g_guard_lock);
    guard = guard_for(username);
    if (ok) {
        guard->fails = 0;
        guard->locked_until = 0;
    } else {
        guard->fails++;
        if (guard->fails >= MAX_LOGIN_FAILS) {
            guard->locked_until = now + LOCKOUT_SECONDS;
            guard->fails = 0;
        }
    }
    pthread_mutex_unlock(&g_guard_lock);

    return ok ? AUTH_OK : AUTH_BAD;
}

auth_reg_result_t auth_register(const char *username, const char *password) {
    if (!username || !password) return AUTH_REG_INVALID;
    if (!valid_username(username) || !valid_password(password)) return AUTH_REG_INVALID;
    if (find_account(username) >= 0) return AUTH_REG_EXISTS;
    if (g_num_accounts >= MAX_ACCOUNTS) return AUTH_REG_INVALID;

    add_account(username, password);
    if (!save_store()) {
        g_num_accounts--;   // roll back: keep memory consistent with disk
        LOG_ERR("Failed to persist new account '%s'", username);
        return AUTH_REG_IO;
    }
    LOG_INFO("Registered new user '%s'", username);
    return AUTH_REG_OK;
}

int auth_num_accounts(void) {
    return g_num_accounts;
}

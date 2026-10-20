/*
 * CH3 offline harness: tests the read-buffer append with actual client_t layout.
 *
 * Modes:
 *   abi             — print ABI info (sizeof, offsets)
 *   self-test       — run the fixed helper's own self-test suite
 *   case <variant> <L> <N> <raw>
 *                   — run one append case; variant = "before" or "fixed"
 *                     raw=1 runs through the buggy path under instrumentation
 *
 * Compile with:
 *   gcc -std=c11 -Wall -Wextra -fsanitize=bounds -fsanitize-trap=bounds \
 *       -DCH3_WITH_BASELINE -I src/ test/ch3_append_harness.c \
 *       src/ws_frame.c src/state_machine.c -o ch3_harness -lws2_32 -lssl -lcrypto
 */
#include "read_buffer.h"
#include <stddef.h>

/* Stub: the harness does not use logging. */
void log_emit(int level, const char *file, int line, const char *fmt, ...) {
    (void)level; (void)file; (void)line; (void)fmt;
}

/* ── Baseline (buggy) append extracted from server.c:76-83 ───────────────── */
#ifdef CH3_WITH_BASELINE
static int baseline_append(client_t *client, const void *data, int n) {
    /* This is the EXACT code from the baseline commit, transcribed as a
       callable function.  The only change: 'break' becomes 'return -1'. */
    int space = (int)sizeof(client->read_buf) - client->read_len;
    if (n > space) {
        return -1;   /* was: break */
    }
    memcpy(client->read_buf + client->read_len, data, n);
    client->read_len += n;
    client->read_buf[client->read_len] = '\0';
    return 0;
}
#endif

/* ── Test infrastructure ─────────────────────────────────────────────────── */
static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #cond); failures++; } } while (0)

static void print_abi(void) {
    printf("{\"int_bytes\":%zu,\"size_t_bytes\":%zu,\"pointer_bytes\":%zu,"
           "\"capacity\":%zu,\"recv_capacity\":%d,"
           "\"offset_buf\":%zu,\"offset_len\":%zu}\n",
           sizeof(int), sizeof(size_t), sizeof(void *),
           sizeof(((client_t *)0)->read_buf), CLIENT_RECV_CAPACITY,
           offsetof(client_t, read_buf), offsetof(client_t, read_len));
}

static int do_append(client_t *c, const void *data, int n, int before) {
#ifdef CH3_WITH_BASELINE
    if (before) return baseline_append(c, data, n);
#else
    if (before) { fprintf(stderr, "baseline unavailable\n"); exit(2); }
#endif
    return client_read_append(c, data, n);
}

static int run_case(int before, int length, int n, int raw) {
    client_t c;
    memset(&c, 0, sizeof(c));
    memset(c.read_buf, 'q', sizeof(c.read_buf));
    c.read_len = length;

    /* Save snapshot to detect mutations on rejection */
    client_t snapshot;
    memcpy(&snapshot, &c, sizeof(c));

    unsigned char data[CLIENT_RECV_CAPACITY];
    memset(data, 'x', sizeof(data));

    const int cap = (int)sizeof(c.read_buf);

    /* For before variant with invalid preconditions, skip */
    if (before && (length < 0 || length >= cap || n <= 0 || n > CLIENT_RECV_CAPACITY))
        return 2;

    const long long index = (long long)length + n;
    const int bad = before && n <= cap - (long long)length && (index < 0 || index >= cap);

    if (raw) {
        fprintf(stderr, "RAW_BASELINE_ACCESS L=%d N=%d index=%lld\n", length, n, index);
        fflush(stderr);
    }

    /* Avoid executing UB during ordinary (non-raw) replay.
       The raw path is run ONLY under bounds-trap instrumentation. */
    if (bad && !raw) {
        printf("{\"variant\":\"before\",\"L\":%d,\"N\":%d,"
               "\"accepted\":true,\"index\":%lld,\"bad_index\":true,"
               "\"executed_write\":false,\"oracle\":\"subobject_index\"}\n",
               length, n, index);
        return 0;
    }

    int rc = do_append(&c, data, n, before);
    int unchanged = memcmp(&c, &snapshot, sizeof(c)) == 0;
    int terminated = rc == 0 && c.read_len >= 0 && c.read_len < cap
                     && c.read_buf[c.read_len] == 0;
    int copied = rc == 0 && n > 0 && n <= CLIENT_RECV_CAPACITY
                 && memcmp(c.read_buf + length, data, (size_t)n) == 0;

    printf("{\"variant\":\"%s\",\"L\":%d,\"N\":%d,\"accepted\":%s,"
           "\"index\":%lld,\"bad_index\":false,\"unchanged\":%s,"
           "\"terminated\":%s,\"copied\":%s,\"read_len\":%d}\n",
           before ? "before" : "fixed", length, n,
           rc == 0 ? "true" : "false", index,
           unchanged ? "true" : "false",
           terminated ? "true" : "false",
           copied ? "true" : "false",
           c.read_len);

    /* Return non-zero if accepted but invariants broken, or rejected but mutated */
    return rc == 0 ? !(terminated && copied) : !unchanged;
}

static int self_test(void) {
    failures = 0;

    /* Test 1: normal append from empty */
    {
        client_t c = {0};
        unsigned char data[] = "hello";
        CHECK(client_read_append(&c, data, 5) == 0);
        CHECK(c.read_len == 5);
        CHECK(memcmp(c.read_buf, "hello", 5) == 0);
        CHECK(c.read_buf[5] == '\0');
    }

    /* Test 2: fill to max safe (capacity - 1 = 8191) */
    {
        client_t c = {0};
        unsigned char data[4096];
        memset(data, 'A', sizeof(data));

        CHECK(client_read_append(&c, data, 4095) == 0);
        CHECK(c.read_len == 4095);
        CHECK(client_read_append(&c, data, 4096) == 0);
        CHECK(c.read_len == 8191);
        CHECK(c.read_buf[8191] == '\0');
    }

    /* Test 3: one more byte should be rejected */
    {
        client_t c = {0};
        unsigned char data[4096];
        memset(data, 'B', sizeof(data));

        client_read_append(&c, data, 4095);
        client_read_append(&c, data, 4096);
        /* Now read_len == 8191, try one more byte */
        int orig_len = c.read_len;
        CHECK(client_read_append(&c, data, 1) == -1);
        CHECK(c.read_len == orig_len);  /* unchanged */
    }

    /* Test 4: reject when total == capacity */
    {
        client_t c = {0};
        unsigned char data[4096];
        memset(data, 'C', sizeof(data));
        client_read_append(&c, data, 4096);
        CHECK(c.read_len == 4096);
        /* 4096 + 4096 = 8192 == capacity: must reject */
        int orig_len = c.read_len;
        CHECK(client_read_append(&c, data, 4096) == -1);
        CHECK(c.read_len == orig_len);
    }

    /* Test 5: NULL / invalid arguments */
    {
        client_t c = {0};
        unsigned char data[10];
        CHECK(client_read_append(NULL, data, 5) == -1);
        CHECK(client_read_append(&c, NULL, 5) == -1);
        CHECK(client_read_append(&c, data, 0) == -1);
        CHECK(client_read_append(&c, data, -1) == -1);
        CHECK(client_read_append(&c, data, CLIENT_RECV_CAPACITY + 1) == -1);
    }

    printf("{\"self_test_failures\":%d}\n", failures);
    return failures;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s abi|self-test|case <before|fixed> <L> <N> <raw>\n", argv[0]);
        return 2;
    }

    if (strcmp(argv[1], "abi") == 0) {
        print_abi();
        return 0;
    }

    if (strcmp(argv[1], "self-test") == 0) {
        return self_test();
    }

    if (strcmp(argv[1], "case") == 0 && argc >= 6) {
        int before = strcmp(argv[2], "before") == 0;
        int length = atoi(argv[3]);
        int n_val = atoi(argv[4]);
        int raw = atoi(argv[5]);
        return run_case(before, length, n_val, raw);
    }

    fprintf(stderr, "Unknown command: %s\n", argv[1]);
    return 2;
}

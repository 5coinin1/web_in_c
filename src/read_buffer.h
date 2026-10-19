#ifndef READ_BUFFER_H
#define READ_BUFFER_H
/*
 * CH3 patch: safe read-buffer append with NUL-terminator headroom.
 *
 * The original server.c code allowed read_len + n == capacity, then wrote
 * '\0' at read_buf[capacity] — one byte past the array.  This helper
 * reserves one byte so the terminator always lands inside the buffer.
 *
 * Used by both the production server and the offline CH3 harness, so the
 * harness tests the exact same code that runs in production.
 */
#include "connection.h"
#include <limits.h>

#define CLIENT_RECV_CAPACITY 4096

/* Append `n` bytes to client->read_buf.  Returns 0 on success, -1 if the
 * data would not fit with the required NUL terminator.  On failure the
 * client object is NOT modified (no partial copy). */
static inline int client_read_append(client_t *client, const void *data, int n) {
    _Static_assert(sizeof(((client_t *)0)->read_buf) <= INT_MAX,
                   "read buffer capacity must fit int");
    if (!client || !data || n <= 0 || n > CLIENT_RECV_CAPACITY) return -1;
    const int capacity = (int)sizeof(client->read_buf);
    const int length = client->read_len;
    if (length < 0 || length >= capacity) return -1;
    /* Key fix: capacity - 1 - length guarantees room for the NUL byte. */
    if (n > capacity - 1 - length) return -1;
    memcpy(client->read_buf + length, data, (size_t)n);
    client->read_len = length + n;
    client->read_buf[client->read_len] = '\0';
    return 0;
}
#endif

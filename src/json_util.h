#ifndef JSON_UTIL_H
#define JSON_UTIL_H

#include <stddef.h>

// Minimal helpers for the small, flat JSON messages used by the protocol.

// Extract a string value for key. Tolerates whitespace around ':' and quotes.
// Returns 0 on success, -1 if the key/value is absent or malformed.
int json_get_string(const char *json, const char *key, char *out, size_t out_size);

// Extract a raw (non-string) value such as an array, e.g. "users":[...].
// Returns 0 on success, -1 if not found.
int json_get_raw(const char *json, const char *key, char *out, size_t out_size);

#endif

#ifndef JSON_UTIL_H
#define JSON_UTIL_H

#include <stddef.h>

// Minimal helpers for the small, flat JSON messages used by the protocol.

// Extract a string value for key. Handles JSON escapes (\" \\ \n \r \t ...).
// Returns 0 on success, -1 if the key/value is absent or malformed.
int json_get_string(const char *json, const char *key, char *out, size_t out_size);

// Extract an integer value for key. Accepts both a bare number (19) and a
// quoted one ("19"). Returns 0 on success, -1 if absent or not numeric.
int json_get_int(const char *json, const char *key, long *out);

// Extract a raw (non-string) value such as an array, e.g. "users":[...].
// Returns 0 on success, -1 if not found.
int json_get_raw(const char *json, const char *key, char *out, size_t out_size);

// Escape src into a JSON string body (escapes ", \, and control characters).
// Output is truncated safely. dst must be non-NULL.
void json_escape(const char *src, char *dst, size_t dst_size);

#endif

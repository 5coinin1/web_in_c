#include "json_util.h"
#include <string.h>
#include <stdio.h>

static int find_value(const char *json, const char *key, const char **out) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);

    const char *p = strstr(json, pattern);
    if (!p) return -1;
    p += strlen(pattern);

    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    if (*p != ':') return -1;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;

    *out = p;
    return 0;
}

int json_get_string(const char *json, const char *key, char *out, size_t out_size) {
    const char *p;
    if (!json || !key || find_value(json, key, &p) != 0) return -1;
    if (*p != '"') return -1;
    p++;

    const char *end = strchr(p, '"');
    if (!end) return -1;

    size_t n = (size_t)(end - p);
    if (n >= out_size) n = out_size - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 0;
}

int json_get_raw(const char *json, const char *key, char *out, size_t out_size) {
    const char *p;
    if (!out || out_size == 0) return -1;
    out[0] = '\0';
    if (!json || !key || find_value(json, key, &p) != 0) return -1;

    char open = *p;
    char close = (open == '[') ? ']' : (open == '{') ? '}' : '"';
    const char *end = strchr(p, close);
    if (!end) return -1;

    size_t n = (size_t)(end - p) + 1;
    if (n >= out_size) n = out_size - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 0;
}

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
    if (!json || !key || !out || out_size == 0) return -1;
    if (find_value(json, key, &p) != 0) return -1;
    if (*p != '"') return -1;
    p++;

    size_t j = 0;
    while (*p && *p != '"') {
        char c = *p;
        if (c == '\\' && p[1]) {
            p++;
            switch (*p) {
                case '"':  c = '"';  break;
                case '\\': c = '\\'; break;
                case '/':  c = '/';  break;
                case 'n':  c = '\n'; break;
                case 'r':  c = '\r'; break;
                case 't':  c = '\t'; break;
                case 'b':  c = '\b'; break;
                case 'f':  c = '\f'; break;
                default:   c = *p;   break;   // e.g. \uXXXX: keep raw
            }
        }
        if (j + 1 < out_size) out[j++] = c;
        p++;
    }
    if (*p != '"') return -1;
    out[j] = '\0';
    return 0;
}

void json_escape(const char *src, char *dst, size_t dst_size) {
    if (!dst || dst_size == 0) return;
    size_t j = 0;
    for (size_t i = 0; src && src[i]; i++) {
        unsigned char c = (unsigned char)src[i];
        const char *rep = NULL;
        char tmp[8];
        switch (c) {
            case '"':  rep = "\\\""; break;
            case '\\': rep = "\\\\"; break;
            case '\n': rep = "\\n";  break;
            case '\r': rep = "\\r";  break;
            case '\t': rep = "\\t";  break;
            default:
                if (c < 0x20) { snprintf(tmp, sizeof(tmp), "\\u%04x", c); rep = tmp; }
        }
        if (rep) {
            size_t n = strlen(rep);
            if (j + n + 1 > dst_size) break;
            memcpy(dst + j, rep, n);
            j += n;
        } else {
            if (j + 1 >= dst_size) break;
            dst[j++] = (char)c;
        }
    }
    dst[j] = '\0';
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

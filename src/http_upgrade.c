#include "http_upgrade.h"
#include <ctype.h>
#include <openssl/sha.h>

// memmem replacement for MinGW
static const char *my_memmem(const char *haystack, size_t hlen,
                             const char *needle, size_t nlen) {
    if (nlen == 0) return haystack;
    if (hlen < nlen) return NULL;
    for (size_t i = 0; i <= hlen - nlen; i++) {
        if (memcmp(&haystack[i], needle, nlen) == 0)
            return &haystack[i];
    }
    return NULL;
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s) - 1;
    while (end > s && isspace((unsigned char)*end)) *end-- = '\0';
    return s;
}

static char *strcasestr_simple(const char *haystack, const char *needle) {
    if (!needle || !*needle) return (char *)haystack;
    size_t nlen = strlen(needle);
    for (size_t i = 0; haystack[i]; i++) {
        if (strncasecmp(&haystack[i], needle, nlen) == 0)
            return (char *)&haystack[i];
    }
    return NULL;
}

int http_parse_request(const char *buf, size_t len, http_request_t *req) {
    if (!buf || !req || len < 4) return -1;

    memset(req, 0, sizeof(*req));

    // Check for \r\n\r\n (end of headers)
    const char *end = my_memmem(buf, len, "\r\n\r\n", 4);
    if (!end) return 0; // incomplete

    // Parse request line
    const char *line_end = my_memmem(buf, len, "\r\n", 2);
    if (!line_end) return -1;

    // Method
    const char *p = buf;
    const char *sp = memchr(p, ' ', line_end - p);
    if (!sp) return -1;
    size_t method_len = sp - p;
    if (method_len >= sizeof(req->method)) return -1;
    memcpy(req->method, p, method_len);
    req->method[method_len] = '\0';

    // Headers
    const char *hdr_start = line_end + 2;
    size_t hdr_len = end - hdr_start;

    char hdr_buf[4096];
    if (hdr_len >= sizeof(hdr_buf)) return -1;
    memcpy(hdr_buf, hdr_start, hdr_len);
    hdr_buf[hdr_len] = '\0';

    // Parse each header line
    char *saveptr;
    char *line = strtok_r(hdr_buf, "\r\n", &saveptr);
    while (line) {
        if (strncasecmp(line, "Sec-WebSocket-Key:", 18) == 0) {
            char *val = trim(line + 18);
            strncpy(req->websocket_key, val, sizeof(req->websocket_key) - 1);
        }
        line = strtok_r(NULL, "\r\n", &saveptr);
    }

    // Validate: must be GET, must have Upgrade: websocket, must have key
    if (strcmp(req->method, "GET") != 0) {
        LOG_ERR("Not GET: '%s'", req->method);
        return -1;
    }

    // Check Upgrade header (in raw buffer)
    if (!strcasestr_simple(buf, "Upgrade: websocket") &&
        !strcasestr_simple(buf, "Upgrade: Websocket")) {
        LOG_ERR("No Upgrade header found");
        return -1;
    }

    // Check Connection header
    if (!strcasestr_simple(buf, "Connection: Upgrade")) {
        LOG_ERR("No Connection header found");
        return -1;
    }

    if (!req->websocket_key[0]) {
        LOG_ERR("No Sec-WebSocket-Key found");
        return -1;
    }

    req->valid = true;
    return 1;
}

bool http_validate_key(const char *key) {
    if (!key) return false;
    size_t len = strlen(key);
    // base64 of 16 bytes = 24 chars (ending in "==")
    if (len != 24) return false;
    for (size_t i = 0; i < len; i++) {
        char c = key[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '='))
            return false;
    }
    return true;
}

// Base64-encode the 20-byte SHA-1 digest into the Sec-WebSocket-Accept key.
static void base64_encode(const unsigned char *input, int length, char *output) {
    const char *table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j;
    for (i = 0, j = 0; i < length; i += 3) {
        uint32_t a = (uint32_t)input[i];
        uint32_t b = (i + 1 < length) ? (uint32_t)input[i + 1] : 0;
        uint32_t c = (i + 2 < length) ? (uint32_t)input[i + 2] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;

        output[j++] = table[(triple >> 18) & 0x3F];
        output[j++] = table[(triple >> 12) & 0x3F];
        output[j++] = (i + 1 < length) ? table[(triple >> 6) & 0x3F] : '=';
        output[j++] = (i + 2 < length) ? table[triple & 0x3F] : '=';
    }
    output[j] = '\0';
}

int http_build_upgrade_response(const char *client_key, char *out_buf, size_t out_buf_size) {
    if (!client_key || !out_buf) return -1;

    // Concatenate key + magic string
    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    char concat[256];
    snprintf(concat, sizeof(concat), "%s%s", client_key, magic);

    // SHA-1 hash
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char *)concat, strlen(concat), hash);

    // Base64 encode
    char accept_key[64];
    base64_encode(hash, SHA_DIGEST_LENGTH, accept_key);

    int len = snprintf(out_buf, out_buf_size,
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Accept: %s\r\n"
        "\r\n",
        accept_key);

    return len;
}

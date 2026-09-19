#ifndef HTTP_UPGRADE_H
#define HTTP_UPGRADE_H

#include "common.h"

typedef struct {
    char method[16];
    char websocket_key[64];
    bool valid;
} http_request_t;

// Parse HTTP request from raw buffer. Returns 1 if complete request parsed, 0 if incomplete, -1 on error.
int http_parse_request(const char *buf, size_t len, http_request_t *req);

// Generate WebSocket upgrade response. Returns response length.
int http_build_upgrade_response(const char *client_key, char *out_buf, size_t out_buf_size);

// Validate WebSocket key (base64 of 16 bytes = 24 chars).
bool http_validate_key(const char *key);

#endif

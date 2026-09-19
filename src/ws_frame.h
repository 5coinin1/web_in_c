#ifndef WS_FRAME_H
#define WS_FRAME_H

#include "common.h"

typedef struct {
    uint8_t  opcode;
    uint64_t payload_len;
    uint8_t *payload;
} ws_frame_t;

// Decode a WebSocket frame from buffer. Returns bytes consumed, or -1 on error.
// After calling, caller owns frame->payload (must free).
int ws_frame_decode(const uint8_t *buf, size_t len, ws_frame_t *frame);

// Free payload allocated by ws_frame_decode
void ws_frame_free(ws_frame_t *frame);

// Build a WebSocket frame into out_buf. Returns total frame size, or -1 on error.
// out_buf must be large enough: 14 + payload_len (max header + mask).
int ws_frame_encode(uint8_t opcode, const uint8_t *payload, uint64_t payload_len,
                    bool mask, uint8_t out_buf[], size_t out_buf_size);

#endif

#include "ws_frame.h"
#include <stdlib.h>
#include <openssl/rand.h>

static uint64_t read_be64(const uint8_t *buf) {
    uint64_t val = 0;
    for (int i = 0; i < 8; i++) {
        val = (val << 8) | buf[i];
    }
    return val;
}

static void write_be64(uint8_t *buf, uint64_t val) {
    for (int i = 7; i >= 0; i--) {
        buf[i] = val & 0xFF;
        val >>= 8;
    }
}

int ws_frame_decode(const uint8_t *buf, size_t len, ws_frame_t *frame) {
    if (!buf || !frame || len < 2) return -1;

    size_t pos = 0;

    // Byte 0: FIN + opcode (fragmentation is not supported; FIN is ignored)
    frame->opcode = buf[0] & 0x0F;

    // Byte 1: MASK + payload length
    bool masked = (buf[1] & 0x80) != 0;
    uint64_t payload_len = buf[1] & 0x7F;
    pos = 2;

    if (payload_len == 126) {
        if (len < pos + 2) return -1;
        payload_len = (uint64_t)((uint16_t)buf[pos] << 8 | buf[pos + 1]);
        pos += 2;
    } else if (payload_len == 127) {
        if (len < pos + 8) return -1;
        payload_len = read_be64(&buf[pos]);
        pos += 8;
    }

    if (payload_len > WS_FRAME_MAX_PAYLOAD) {
        LOG_ERR("Frame payload too large: %llu", (unsigned long long)payload_len);
        return -1;
    }

    frame->payload_len = payload_len;

    // Mask key (4 bytes) — present only if masked bit is set
    uint8_t mask_key[4] = {0};
    if (masked) {
        if (len < pos + 4) return -1;
        memcpy(mask_key, &buf[pos], 4);
        pos += 4;
    }

    // Payload
    if (len < pos + payload_len) return -1;

    if (payload_len > 0) {
        frame->payload = (uint8_t *)malloc((size_t)payload_len);
        if (!frame->payload) return -1;
        memcpy(frame->payload, &buf[pos], (size_t)payload_len);

        // Unmask if needed
        if (masked) {
            for (uint64_t i = 0; i < payload_len; i++) {
                frame->payload[i] ^= mask_key[i % 4];
            }
        }
    } else {
        frame->payload = NULL;
    }

    pos += (size_t)payload_len;
    return (int)pos;
}

void ws_frame_free(ws_frame_t *frame) {
    if (frame && frame->payload) {
        free(frame->payload);
        frame->payload = NULL;
    }
}

int ws_frame_encode(uint8_t opcode, const uint8_t *payload, uint64_t payload_len,
                    bool mask, uint8_t out_buf[], size_t out_buf_size) {
    size_t pos = 0;

    // Header: FIN=1 + opcode
    out_buf[pos++] = 0x80 | (opcode & 0x0F);

    // MASK bit + payload length
    out_buf[pos] = mask ? 0x80 : 0x00;

    if (payload_len < 126) {
        out_buf[pos++] |= (uint8_t)payload_len;
    } else if (payload_len <= 0xFFFF) {
        out_buf[pos++] |= 126;
        if (pos + 2 > out_buf_size) return -1;
        out_buf[pos++] = (payload_len >> 8) & 0xFF;
        out_buf[pos++] = payload_len & 0xFF;
    } else {
        out_buf[pos++] |= 127;
        if (pos + 8 > out_buf_size) return -1;
        write_be64(&out_buf[pos], payload_len);
        pos += 8;
    }

    // Mask key (random 4 bytes) + masked payload
    if (mask) {
        if (pos + 4 > out_buf_size) return -1;
        uint8_t mask_key[4];
        if (RAND_bytes(mask_key, sizeof(mask_key)) != 1) {
            uint32_t r = (uint32_t)rand();
            mask_key[0] = (uint8_t)(r >> 24);
            mask_key[1] = (uint8_t)(r >> 16);
            mask_key[2] = (uint8_t)(r >> 8);
            mask_key[3] = (uint8_t)r;
        }
        memcpy(&out_buf[pos], mask_key, 4);
        pos += 4;

        if (pos + payload_len > out_buf_size) return -1;
        for (uint64_t i = 0; i < payload_len; i++) {
            out_buf[pos + i] = payload[i] ^ mask_key[i % 4];
        }
        pos += (size_t)payload_len;
    } else {
        if (pos + payload_len > out_buf_size) return -1;
        if (payload_len > 0) {
            memcpy(&out_buf[pos], payload, (size_t)payload_len);
        }
        pos += (size_t)payload_len;
    }

    return (int)pos;
}

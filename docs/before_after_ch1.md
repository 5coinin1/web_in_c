# Bảng before/after — Chương 1

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-693 | `src/state_machine.c` — P1 | join_bypass: P1 FAIL; trace FIRST_BYTES → HTTP_UPGRADE_VALID → JOIN_OK; C buggy vào IN_ROOM | P1 PASS; C gốc từ chối JOIN_OK | Python CTL + C replay |
| CWE-693 | `src/state_machine.c` — P4 | message_guard: P4 FAIL; trace FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → MESSAGE_VALID | P4 PASS | Python CTL |
| CWE-693 | `src/state_machine.c` — P5/P7 | stale_auth: P5/P7 FAIL; trace FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → LOGOUT | P5/P7 PASS | Python CTL |
| CWE-667 | `src/session.c` | biến thể buggy: cả 2 session cùng active | `AG(!(session_A & session_B))` PASS | C product model |
| CWE-693 (CWE-667) | `src/room.c` | biến thể buggy delete: I1 stranded client | I1/I2/I3 PASS | C product model |

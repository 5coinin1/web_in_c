# Bảng before/after tổng hợp — 4 chương

> Bảng chuẩn hóa theo mẫu Phần 5 của `report_guide.pdf`:
> `CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh`.
> Mỗi dòng tương ứng 1 phát hiện trong `docs/cwe_cve_summary.md`.

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-693 | Ch1 — `src/state_machine.c`, P1 | `join_bypass`: P1 FAIL; trace `FIRST_BYTES → HTTP_UPGRADE_VALID → JOIN_OK`; C buggy vào `IN_ROOM` | P1 PASS; C gốc từ chối `JOIN_OK` | Python CTL + C replay |
| CWE-693 | Ch1 — `src/state_machine.c`, P4 | `message_guard`: P4 FAIL; trace `FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → MESSAGE_VALID` | P4 PASS | Python CTL |
| CWE-693 | Ch1 — `src/state_machine.c`, P5/P7 | `stale_auth`: P5/P7 FAIL; trace `FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → LOGOUT` | P5/P7 PASS | Python CTL |
| CWE-667 | Ch1 — `src/session.c` | Biến thể buggy: cả 2 session cùng active; counterexample `(A_logged=1, B_logged=1)` | `AG(!(session_A & session_B))` PASS | C product model |
| CWE-693 (CWE-667) | Ch1 — `src/room.c` | Biến thể buggy delete: I1 stranded client; counterexample 4 bước / 7 bước | I1/I2/I3 PASS | C product model |
| CWE-193 | Ch2 — `src/auth.c:114` | 11-byte store được chấp nhận; ASan `heap-buffer-overflow` READ size 1 tại `src/bytes.h:30` | `len < 12`; parser `rc=-1`, không ASan | ASan/UBSan + harness |
| CWE-787 (CWE-129) | Ch2 — `src/auth.c:122-147` | `count=300` ghi quá `g_accounts[256]`; ASan `global-buffer-overflow` WRITE size 32 tại `src/auth.c:142` | `count` cap tại `MAX_ACCOUNTS`; `accounts=256`, không ASan | ASan/UBSan + harness |
| CWE-125 (CWE-190) | Ch2 — `src/auth.c:130-146` | Record ngắn bị đọc quá heap; ASan `heap-buffer-overflow` READ size 32 tại `src/auth.c:142` | Kiểm tra `off > len` / `RECORD_SIZE > len - off`; `accounts=0`, không ASan | ASan/UBSan + harness |
| CWE-193 | Ch3 — `src/read_buffer.h` | `L=4096,N=4096 → index=8192`; SMT SAT; C harness `bad_index=true` | Guard `N ≤ C-1-L`; SMT UNSAT; harness `accepted=false` | Z3 + C harness |
| CWE-190 | Ch3 — `src/read_buffer.h` | Nguy cơ tràn signed int32 nếu không giới hạn miền | SMT `signed_overflow=UNSAT` trong miền `0≤L<8192, 0<N≤4096` | Z3 |
| CWE-787 | Ch3 — `src/read_buffer.h` | Nếu ghi NUL tại index 8192 → ghi quá mảng | Index ≤ 8191; không ghi quá | Z3 + C harness |
| CWE-193 (CWE-125/787) | Ch4 — `src/auth.c:122` / `src/bytes.h:30` | Fuzzing tìm crash: seeded 17 lần, white-box 1 lần; ASan `heap-buffer-overflow` | Fixed build không crash; parser `rc=-1`; fuzzing không tìm thấy crash | Fuzzer + ASan + gcov |

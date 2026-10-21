# Chương 1 — Mô hình hóa & kiểm chứng hình thức (Kripke + BMC)

> Sinh viên: _điền tên/MSSV_ — Môn: An toàn phần mềm (CSE703093)
> Ngày sinh báo cáo: 2026-10-21 — Nguồn: `python/ch1_kripke/generated/`
> Toolchain: Python 3.14 + mô hình C (`src/state_machine.c`, `src/kripke.c`)

## 1. Phạm vi và mô hình

Đối tượng: máy trạng thái kết nối WebSocket của server chat, dùng chung bởi
runtime C và mô hình kiểm chứng:

```
STATE_IDLE → STATE_HTTP_HANDSHAKE → STATE_WS_CONNECTED
           → STATE_AUTHENTICATED → STATE_IN_ROOM
           → STATE_AUTHENTICATED (LEAVE / ROOM_CLOSED)
           → STATE_CLOSED (DISCONNECT, terminal)
```

Kripke structure:

- **S**: 6 trạng thái lõi (IDLE … CLOSED); mô hình lệnh mở rộng thành 8–11
  trạng thái tuỳ mutation.
- **S0**: `STATE_IDLE` (model lệnh: `S0`).
- **R**: `client_state_next()` / bảng chuyển `core_matrix.json` (6 state × 10 event).
- **L**: `ws_open`, `authenticated`, `in_room`, `member`, `message_accepted`,
  `logged_out`, `closed`, … (xem `python/ch1_kripke/properties.py`).

Có 3 tầng kiểm chứng:
1. **Lõi C** — `test/ch1_kripke.c` chạy 6 trạng thái, 10 sự kiện; BMC + đối
   chiếu bảng chuyển C.
2. **Model lệnh Python** — 14 thuộc tính CTL/mỗi model, 4 biến thể
   (đúng + 3 lỗi cố ý), replay lại đúng chuỗi sự kiện C.
3. **Product automaton** — 2 kết nối, session, phòng dùng chung.

## 2. Thuộc tính CTL trên mô hình đúng

| ID | Công thức | Ý nghĩa | Kết quả |
|---|---|---|---|
| P1 | `AG(in_room -> authenticated)` | Vào phòng bắt buộc đã đăng nhập | PASS |
| P2 | `AG(authenticated -> ws_open)` | Đã đăng nhập bắt buộc WebSocket đã mở | PASS |
| P3 | `AG(closed -> NOT(authenticated OR member OR ws_open))` | CLOSED không còn giữ bất kỳ trạng thái sống | PASS |
| P4 | `AG(message_accepted -> (authenticated AND member AND in_room))` | Chỉ nhận MESSAGE khi đã login + ở trong phòng | PASS |
| P5 | `AG(logged_out -> NOT(authenticated OR member OR in_room))` | Sau LOGOUT không còn authenticated/member/in_room | PASS |
| P6 | `AG(member <-> in_room)` | member và in_room luôn tương đương | PASS |
| P7 | `AG(authenticated -> (phase_AUTHENTICATED OR phase_IN_ROOM))` | authenticated phải ở phase AUTHENTICATED hoặc IN_ROOM | PASS |
| R1 | `EF authenticated` | Có thể đạt authenticated | PASS |
| R2 | `EF in_room` | Có thể đạt in_room | PASS |
| R3 | `EF message_accepted` | Có thể đạt message_accepted | PASS |
| R4 | `EF logged_out` | Có thể đạt logged_out | PASS |
| R5 | `EF closed` | Có thể đạt closed | PASS |
| L1 | `AG(ws_open -> EF(in_room OR closed))` | Từ ws_open luôn có đường tới in_room hoặc closed | PASS |
| L2 | `AG(in_room -> EF(authenticated AND NOT in_room))` | Từ in_room luôn có đường quay lại authenticated | PASS |

- 7 thuộc tính an toàn (`AG`), 5 khả đạt (`EF`), 2 sống còn (`AG ... EF`).
- Tổng **185 test PASS** (bao gồm đối chiếu C, replay lifecycle, counterexample,
  shared model, kiểm tra checker trên đồ thị đồ chơi).
- Completeness threshold của model lệnh: **k* = 5**; của lõi C
  (`kripke_completeness_threshold()`): **k* = 4`.

## 3. Mutation và counterexample

| Model | Mô tả mutation | Số thuộc tính FAIL | Thuộc tính FAIL |
|---|---|---|---|
| `none` | Mô hình đúng (reviewed contract) | 0 | — |
| `join_bypass` | Bỏ qua LOGIN: JOIN_OK từ WS_CONNECTED | 2 | `P1`, `P4` |
| `message_guard` | Cho MESSAGE khi chưa vào phòng | 1 | `P4` |
| `stale_auth` | Giữ auth_history sau LOGOUT | 2 | `P5`, `P7` |

- **join_bypass** (P1, P4): trace ngắn nhất `FIRST_BYTES → HTTP_UPGRADE_VALID → JOIN_OK`. C replay:
  `buggy` nhận `JOIN_OK` khi chưa login → `IN_ROOM`; bản gốc từ chối
  (`WS_CONNECTED`). Xem `results/ch1/counterexamples/c_counterexample_replay.json`.
- **message_guard** (P4): trace `FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → MESSAGE_VALID` — nhận MESSAGE trước khi vào phòng.
- **stale_auth** (P5, P7): trace `FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → LOGOUT` — sau LOGOUT vẫn còn
  `auth_history`, nên `authenticated` vẫn đúng.

## 4. Product automaton (2 kết nối / session / phòng)

| Model | Mô tả | Thuộc tính FAIL |
|---|---|---|
| `shared_same_account` | 2 kết nối cùng tài khoản — single session | — |
| `shared_distinct_accounts` | 2 tài khoản khác nhau — cùng phòng | — |
| `shared_distinct_accounts_buggy_delete` | 2 tài khoản — xóa phòng lỗi (role B không bị evict) | `deleted_room_empty` |

- `shared_same_account`: giữ **single session** — không thể cả 2 kết nối cùng
  authenticated.
- `shared_distinct_accounts`: 2 tài khoản có thể cùng login và cùng vào phòng.
- `shared_distinct_accounts_buggy_delete`: `deleted_room_empty` FAIL — role B
  không bị evict khi phòng bị xóa (mô hình lỗi cố ý).

## 5. Bằng chứng từ mã C

```text
[PASS] properties(IDLE)
[PASS] properties(HTTP_HANDSHAKE)
[PASS] properties(WS_CONNECTED)
[PASS] properties(AUTHENTICATED)
[PASS] properties(IN_ROOM)
[PASS] properties(CLOSED)
[PASS] progress reachable from every connected state
[INFO] completeness threshold k* = 4
[PASS] AG(!(session_A & session_B)) holds
[SESSION] counterexample: (A_logged=1, B_logged=1) -> both sessions active
[PASS] buggy variant: counterexample found (as expected)
--- Tier-3: room product (2 roles + shared room, 216 states) ---
[PASS] I1/I2/I3 hold on every reachable state
      counterexample path (4 steps):
      violated: I1 stranded client: room reference and state machine disagree
[PASS] buggy variant caught: clears room ref, keeps STATE_IN_ROOM
      counterexample path (7 steps):
      violated: I2 num_clients does not match the real member count
[PASS] buggy variant caught: evict loop stops at first member
      counterexample path (4 steps):
      violated: I2 num_clients does not match the real member count
[PASS] buggy variant caught: forgets num_clients = 0
--- Tier-3b: code-faithful LEAVE (window check) ---
       The Tier-3 (atomic LEAVE) model does NOT capture it.
```

- Tier-2 session: `AG(!(session_A & session_B))` đúng; biến thể buggy cho
  counterexample `(A_logged=1, B_logged=1)`.
- Tier-3 room product (216 trạng thái): I1/I2/I3 đúng; biến thể buggy bị bắt với
  counterexample 4 bước (I1 stranded client) và 7 bước (members/capacity).
- BMC lõi C: `k* = 4`; model lệnh Python: `k* = 5`.

## 6. Bảng before/after (Chương 1)

| CWE | Vị trí | Trạng thái v0 (mutation) | Trạng thái v1 (safe) | Công cụ xác minh |
|---|---|---|---|---|
| CWE-693 | `src/state_machine.c` — P1 | join_bypass: P1 FAIL, trace `FIRST_BYTES → HTTP_UPGRADE_VALID → JOIN_OK` | P1 PASS | Python CTL + C replay |
| CWE-693 | `src/state_machine.c` — P4 | message_guard: P4 FAIL, trace `FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → MESSAGE_VALID` | P4 PASS | Python CTL |
| CWE-693 | `src/state_machine.c` — P5/P7 | stale_auth: P5/P7 FAIL, trace `FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → LOGOUT` | P5/P7 PASS | Python CTL |
| CWE-667 | `src/session.c` — session mutex | buggy variant: cả 2 session cùng active | `AG(!(session_A & session_B))` PASS | C product model |
| CWE-693 (CWE-667) | `src/room.c` — room product | buggy delete: I1 stranded client | I1/I2/I3 PASS | C product model |

> Ánh xạ CWE theo bảng của môn: vi phạm CTL → **CWE-693** (Protection Mechanism
> Failure); vi phạm loại trừ lẫn nhau/session → **CWE-667** (Improper Locking).
> Các mã cụ thể hơn có thể dùng: CWE-306 (thiếu xác thực), CWE-862 (thiếu
> authorization), CWE-613 (session không hết hạn).

## 7. Hạn chế

- Mô hình là abstraction của command boundary, không phải kiểm chứng
  thread scheduling / network end-to-end.
- Checker hỗ trợ `AG`, `EF`, `AG ... EF` (subset CTL đủ cho 14 thuộc tính);
  không phải full CTL (AF/EG/AX/EX).
- Mutation là mô hình hóa lỗi cố ý, không phải build production bị lỗi.
- `leave_window.json` là diagnostic về cửa sổ không atomic của LEAVE nhiều bước;
  không khẳng định data race cụ thể.

## 8. Bằng chứng

- `results/ch1/ch1_kripke_c.txt` — log runner C (BMC, Tier-2/3, counterexample).
- `results/ch1/verification.txt` — log Python 185 test.
- `results/ch1/results.json` — kết quả từng thuộc tính.
- `results/ch1/properties.csv` — bảng thuộc tính + kết quả model đúng.
- `results/ch1/summary.txt` — tóm tắt số test/threshold.
- `results/ch1/counterexamples/` — join_bypass, message_guard, stale_auth,
  c_counterexample_replay.
- `results/ch1/core_matrix.json` — bảng 6×10.
- `python/ch1_kripke/generated/` — toàn bộ JSON/CSV/DOT gốc.

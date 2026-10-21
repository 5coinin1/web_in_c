# Chương 3 — Kiểm chứng SMT/BMC cho read-buffer append

> Sinh viên: _điền tên/MSSV_ — Môn: An toàn phần mềm (CSE703093)
> Ngày sinh báo cáo: 2026-10-21 — Nguồn: `results/ch3/`
> Toolchain: Z3 (xem `results/ch3/provenance.json`), gcc MinGW cho C harness

## 1. Phạm vi và mô hình

Đối tượng: `client_read_append()` trong `src/read_buffer.h`, được gọi từ
`src/server.c:77` để nối dữ liệu `recv()` vào `client->read_buf`.

```c
int space = (int)sizeof(client->read_buf) - client->read_len;  // 8192 - L
if (n > space) break;                                          // LỖI: cho phép L+n == 8192
memcpy(client->read_buf + client->read_len, recv_buf, n);
client->read_len += n;
client->read_buf[client->read_len] = '\0';                     // ghi index 8192 → OOB
```

Mô hình SMT:

- `L = read_len` trước khi append, `0 ≤ L < 8192` (BV32, signed).
- `N = số byte recv()` trong một lần, `0 < N ≤ 4096`.
- `C = 8192` (capacity của `read_buf`).
- Guard cũ: `N ≤ C - L`.
- An toàn: `L + N < C` (index của NUL phải `< C`).
- Guard mới: `N ≤ C - 1 - L` (chừa 1 byte cho NUL).
- Kiểm tra tràn: `C - L` và `L + N` không vượt signed int32 (mở rộng 33 bit).

## 2. Kết quả SMT (6 query)

| Query | Diễn giải | Kết quả | Witness | Trạng thái |
|---|---|---|---|---|
| `before_violation` | Guard cũ: tồn tại (L,N) được nhận nhưng index = L+N ≥ 8192 | **SAT** (kỳ vọng SAT) | `{'L': 4096, 'N': 4096, 'index': 8192}` | PASS |
| `fixed_violation` | Guard mới có bao giờ để index ≥ 8192? | **UNSAT** (kỳ vọng UNSAT) | — | PASS |
| `non_vacuity` | Guard mới vẫn nhận input hợp lệ lấp đầy buffer? | **SAT** (kỳ vọng SAT) | `{'N': 1, 'L': 8190, 'index': 8191}` | PASS |
| `signed_overflow` | Có tràn signed int32 trong miền đầu vào? | **UNSAT** (kỳ vọng UNSAT) | — | PASS |
| `invariant_base` | I(0) đúng? (phủ định → UNSAT) | **UNSAT** (kỳ vọng UNSAT) | — | PASS |
| `invariant_step` | I(L) ∧ guard ⇒ I(L+N)? (phủ định → UNSAT) | **UNSAT** (kỳ vọng UNSAT) | — | PASS |

- **before_violation = SAT** với `L=4096, N=4096 → index=8192` — đúng bằng
  counterexample của lỗi thật.
- **fixed_violation = UNSAT** — guard mới không bao giờ để index ≥ 8192.
- **non_vacuity = SAT** — guard mới vẫn nhận input hợp lệ (`L=8190, N=1 → 8191`),
  nên không phải "khóa cứng" mọi input.
- **signed_overflow = UNSAT** — trong miền `0 ≤ L < 8192`, `0 < N ≤ 4096`,
  không có tràn signed int32.
- **invariant_base / invariant_step = UNSAT** — `I(L) = 0 ≤ L < 8192` là
  inductive invariant với guard mới.

Tổng: **12/12 query đúng kỳ vọng**. File SMT-LIB2: `results/ch3/smt2/*.smt2`.

## 3. BMC nhiều vòng recv

| Query | Diễn giải | Kết quả | Witness | Trạng thái |
|---|---|---|---|---|
| `bmc_k1_before` | k=1, guard cũ | **UNSAT** | — | PASS |
| `bmc_k1_fixed` | k=1, guard mới | **UNSAT** | — | PASS |
| `bmc_k2_before` | k=2, guard cũ | **SAT** | `{'N_0': 4096, 'N_1': 4096}` | PASS |
| `bmc_k2_fixed` | k=2, guard mới | **UNSAT** | — | PASS |
| `bmc_k3_before` | k=3, guard cũ | **SAT** | `{'N_0': 2727, 'N_1': 4096, 'N_2': 1369}` | PASS |
| `bmc_k3_fixed` | k=3, guard mới | **UNSAT** | — | PASS |

- k=1: một lần recv tối đa 4096 byte từ buffer rỗng → chưa thể chạm 8192 (UNSAT).
- k=2: `N0=4096, N1=4096` → index 8192 (SAT) — lỗi xuất hiện sau 2 vòng.
- k=3: `N0=2727, N1=4096, N2=1369` → index 8192 (SAT).
- Guard mới: cả k=1..3 đều UNSAT.

## 4. C harness (offline boundary tests)

Compile: `returncode=0` với `-fsanitize=bounds -fsanitize-trap=bounds`
(MinGW). Kết quả **8/8 case PASS**:

| Case | Mô tả | rc | Output rút gọn |
|---|---|---|---|
| `before_L4096_N4096` | SMT witness: total=8192, BAD INDEX | 0 | `{"variant":"before","L":4096,"N":4096,"accepted":true,"index":8192,"bad_index":true,"executed_write":false,"oracle":"...` |
| `fixed_L4096_N4096` | Fixed rejects: total would be 8192 | 0 | `{"variant":"fixed","L":4096,"N":4096,"accepted":false,"index":8192,"bad_index":false,"unchanged":true,"terminated":fa...` |
| `before_L4095_N4096` | Valid: total=8191, last safe index | 0 | `{"variant":"before","L":4095,"N":4096,"accepted":true,"index":8191,"bad_index":false,"unchanged":false,"terminated":t...` |
| `fixed_L4095_N4096` | Fixed accepts: total=8191 | 0 | `{"variant":"fixed","L":4095,"N":4096,"accepted":true,"index":8191,"bad_index":false,"unchanged":false,"terminated":tr...` |
| `fixed_L8191_N1` | Fixed rejects: total would be 8192 | 0 | `{"variant":"fixed","L":8191,"N":1,"accepted":false,"index":8192,"bad_index":false,"unchanged":true,"terminated":false...` |
| `fixed_L0_N4096` | Fixed accepts from empty | 0 | `{"variant":"fixed","L":0,"N":4096,"accepted":true,"index":4096,"bad_index":false,"unchanged":false,"terminated":true,...` |
| `abi` | ABI layout | 0 | `{"int_bytes":4,"size_t_bytes":8,"pointer_bytes":8,"capacity":8192,"recv_capacity":4096,"offset_buf":72,"offset_len":8...` |
| `self_test` | Fixed self-test | 0 | `{"self_test_failures":0}` |

- `before_L4096_N4096`: accepted=true, index=8192, bad_index=true — tái hiện
  đúng witness SMT.
- `fixed_L4096_N4096`: accepted=false, unchanged=true — bản vá từ chối.
- `fixed_L4095_N4096`: accepted=true, index=8191 — biên hợp lệ cuối cùng.
- `fixed_L8191_N1`: accepted=false — chừa đúng 1 byte cho NUL.
- `fixed_L0_N4096`: accepted=true — vẫn hoạt động từ buffer rỗng.

## 5. Bảng before/after (Chương 3)

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-193 | `src/read_buffer.h` (trước đây `src/server.c:76-83`) | `L=4096,N=4096 → index=8192`; SMT SAT; C harness `bad_index=true` | guard `N ≤ C-1-L`; SMT UNSAT; harness `accepted=false` | Z3 + C harness |
| CWE-190 | `src/read_buffer.h` | `signed_overflow` có thể xảy ra nếu không giới hạn miền | SMT UNSAT trong miền `0≤L<8192, 0<N≤4096` | Z3 |
| CWE-787 | `src/read_buffer.h` | nếu ghi NUL tại index 8192 → ghi quá mảng | index ≤ 8191, không ghi quá | Z3 + harness |

## 6. Code trước/sau

Trước (v0 — `src/server.c`):

```c
int space = (int)sizeof(client->read_buf) - client->read_len;
if (n > space) { break; }
memcpy(client->read_buf + client->read_len, recv_buf, n);
client->read_len += n;
client->read_buf[client->read_len] = '\0';   /* OOB khi read_len + n == 8192 */
```

Sau (v1 — `src/read_buffer.h`):

```c
/* src/read_buffer.h - client_read_append() */
if (n > capacity - 1 - length) return -1;     /* chừa 1 byte cho NUL */
memcpy(client->read_buf + length, data, (size_t)n);
client->read_len = length + n;
client->read_buf[client->read_len] = '\0';   /* index <= capacity - 1 */
```

## 7. Hạn chế

- Chỉ phân tích **một hàm** `client_read_append()`; BTL_01 gợi ý 2–3 hàm. Có thể
  bổ sung `auth_store_parse()` (`count`, `off = 12 + i*88`, `len`) để đủ độ phủ.
- Mô hình dùng `int` 32-bit; trên 64-bit `size_t` rộng hơn, nhưng capacity
  8192 nên miền vẫn an toàn.
- Chưa mô hình hóa alignment (record 88 byte đã align 8; có thể bổ sung nếu cần).
- C harness chạy trên MinGW, không có ASan; `-fsanitize=bounds` đủ bắt index.
  Trên WSL có thể chạy lại với ASan nếu muốn.
- BMC chỉ tới k=3; k=2 đã đủ tìm counterexample.

## 8. Bằng chứng

- `results/ch3/results.json` — kết quả 6 SMT + 6 BMC + 8 C case.
- `results/ch3/summary.txt` — tóm tắt 12/12 query + 8/8 case.
- `results/ch3/verification.txt` — log chạy.
- `results/ch3/smt2/*.smt2` — 12 file SMT-LIB2.
- `results/ch3/provenance.json` — Z3 version, SHA-256 nguồn, git HEAD.
- `results/ch3/ch3_harness.exe` — harness (không commit nhị phân; build lại bằng `run.py`).

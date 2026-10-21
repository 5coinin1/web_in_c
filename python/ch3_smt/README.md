# Chương 3 — SMT/BMC cho read-buffer append

Mục tiêu: `client_read_append()` trong `src/read_buffer.h` (gọi từ
`src/server.c:77`) — nối dữ liệu `recv()` vào `client->read_buf` (8192 byte,
mỗi lần recv tối đa 4096 byte) và ghi NUL terminator.

## Lỗi

```c
int space = (int)sizeof(client->read_buf) - client->read_len;
if (n > space) break;                 // cho phép read_len + n == 8192
memcpy(client->read_buf + client->read_len, recv_buf, n);
client->read_len += n;
client->read_buf[client->read_len] = '\0';   // ghi index 8192 → OOB
```

## Chạy

Trên Windows (MinGW gcc — mặc định của `run.py`):

```powershell
py -3 python/ch3_smt/run.py --output results/ch3
py -3 python/ch3_smt/report.py
```

Trong WSL/Linux, `run.py` tự dùng `gcc` + stub OpenSSL (không cần `libssl-dev`):

```bash
python3 python/ch3_smt/run.py --output results/ch3
python3 python/ch3_smt/report.py
```

## Kết quả

| Query | Kết quả | Ý nghĩa |
|---|---|---|
| `before_violation` | SAT `L=4096,N=4096,index=8192` | guard cũ cho phép OOB |
| `fixed_violation` | UNSAT | guard mới không bao giờ OOB |
| `non_vacuity` | SAT `L=8190,N=1,index=8191` | guard mới vẫn dùng được |
| `signed_overflow` | UNSAT | không tràn int32 trong miền |
| `invariant_base/step` | UNSAT | `0 ≤ L < 8192` là inductive invariant |
| BMC k=1..3 | before: UNSAT/SAT/SAT; fixed: UNSAT | lỗi xuất hiện sau 2 vòng recv |
| C harness | 8/8 PASS | witness SMT tái hiện đúng |

## Đầu ra

- `results/ch3/results.json` — 6 SMT + 6 BMC + 8 C case.
- `results/ch3/verification.txt` — log chạy.
- `results/ch3/smt2/*.smt2` — 12 file SMT-LIB2.
- `results/ch3/provenance.json` — Z3 version, SHA-256 nguồn, git HEAD.
- `docs/findings_ch3.md` — báo cáo đầy đủ + before/after.
- `docs/before_after_ch3.md` — bảng before/after.

## Ghi chú

- Chỉ phân tích một hàm; BTL_01 gợi ý 2–3 hàm. Có thể bổ sung
  `auth_store_parse()` (`count`, `off = 12 + i*88`, `len`) để tăng độ phủ.
- Chưa mô hình hóa alignment; `RECORD_SIZE = 88` đã align 8.
- C harness dùng `-fsanitize=bounds -fsanitize-trap=bounds`; trên WSL có thể
  thay bằng ASan nếu muốn.

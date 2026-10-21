# Chương 2 — Memory Safety Audit

Kiểm toán bộ nhớ cho parser `auth_store_parse()` trong `src/auth.c` (file
`server_data/accounts.dat`, magic `WSAC`).

## Lỗ hổng mục tiêu

| ID | CWE | Vị trí | Mô tả | PoC |
|---|---|---|---|---|
| CH2-01 | CWE-193 | `src/auth.c:114` | `len < 11` thay vì `len < 12`; `get_u32(buf+8)` đọc 1 byte quá biên | `poc_offbyone.dat` |
| CH2-02 | CWE-787 | `src/auth.c:122-147` | `count` từ file không cap `MAX_ACCOUNTS`; ghi quá `g_accounts[256]` | `poc_count.dat` |
| CH2-03 | CWE-125 | `src/auth.c:130-146` | `off` không kiểm tra với `len`; đọc quá heap | `poc_short.dat` |

Ba lỗi được cấy có chủ đích, bật bằng `-DVULN`; bản mặc định là bản vá.

## Chạy

Trên Windows, dùng WSL (ASan/UBSan không có trên MinGW):

```powershell
py -3 python/ch2_memory_safety/run_ch2.py
```

Script tự gọi `wslpath` và chạy lại trong WSL Ubuntu. Trong WSL/Linux:

```bash
python3 python/ch2_memory_safety/run_ch2.py
```

Chạy từng phần:

```bash
python3 python/ch2_memory_safety/static_check.py   # cppcheck + pattern scanner
python3 python/ch2_memory_safety/asan_runner.py    # build + ASan/UBSan + PoCs
python3 python/ch2_memory_safety/report.py         # sinh docs/findings_ch2.md
```

Test nhanh package:

```bash
python3 python/tests/test_ch2_memory_safety.py     # 5 test, không cần pytest
```

## Kết quả

- `results/ch2/static_summary.json` — cppcheck (vuln/fixed) + pattern findings.
- `results/ch2/cppcheck_vuln.xml/.txt`, `cppcheck_fixed.xml/.txt`.
- `results/ch2/pattern_scan.txt/.json`.
- `results/ch2/asan/vuln_poc_*.txt` — log ASan đầy đủ.
- `results/ch2/asan/fixed_poc_*.txt` — log bản vá.
- `results/ch2/results.json` — dữ liệu có cấu trúc (error/access/size/frame).
- `results/ch2/summary.txt` — bảng tóm tắt.
- `docs/findings_ch2.md` — báo cáo Chương 2 (5 mục cho mỗi CWE).
- `docs/before_after_ch2.md` — bảng before/after.

Kỳ vọng:

```text
poc_count.dat     global-buffer-overflow  WRITE size 32  src/auth.c:142
poc_short.dat     heap-buffer-overflow    READ  size 32  src/auth.c:142
poc_offbyone.dat  heap-buffer-overflow    READ  size 1   src/bytes.h:30
fixed (all 3)     no ASan, accounts=256 / 0, parser rc=-1
```

## Ghi chú

- Pattern scanner lấy ý tưởng rule-based từ `ch2_memsafe/pattern_scanner.py`
  của toolkit, bổ sung rule theo ngữ cảnh (`count`/`off`/`len`) cho parser.
- `cppcheck --enable=all` **không** phát hiện 3 lỗi biên này (false negative);
  pattern scanner và ASan mới phát hiện. Đây là nội dung thảo luận trong báo cáo.
- Build dùng `-std=gnu11` vì `common.h` cần `struct timeval` và `readlink`
  trong chế độ POSIX; nếu muốn `-std=c11` nghiêm ngặt, thêm
  `#include <sys/time.h>` và `-D_DEFAULT_SOURCE`.
- Stub OpenSSL nằm ở `python/ch4_fuzzing/stubs` để không cần `libssl-dev`.
- PoC được sinh tự động bởi `tools/make_pocs.py` vào `results/ch2/pocs/`.

# python/ — bộ công cụ theo 4 chương của học phần

`python/` chia thành **4 thư mục theo chương** (đúng 4 hướng trong `title.txt`),
mỗi chương một package Python độc lập; mã C của dự án (`src/`, `test/`) là chủ
thể để các chương phân tích.

```
python/
  ch1_kripke/            # Ch1: Mô hình hóa & Kiểm chứng hình thức (Kripke + BMC)  (KHUNG)
  ch2_memory_safety/     # Ch2: Kiểm toán an toàn bộ nhớ C                          (KHUNG)
  ch3_smt/               # Ch3: Kiểm chứng số học/alignment bằng SMT (Z3)          (KHUNG)
  ch4_fuzzing/           # Ch4: Fuzzing (black-box vs white-box)               <-- ĐÃ LÀM
    __init__.py
    build.py             # biên dịch target (--coverage, -fsanitize=address, -DVULN)
    fuzzing.py           # run / coverage / crash-oracle / black-box / coverage-guided
    whitebox.py          # dựng input theo cấu trúc + giải cổng magic bằng Z3
    seeds.py             # seed corpus
    stubs/openssl/*.h    # stub OpenSSL (parser không dùng crypto)
    stubs/stub_openssl.c
    _work/               # binary + .gcno/.gcda + seeds (sinh khi chạy)
  tests/
    test_ch4_fuzzing.py  # pytest HOẶC chạy độc lập (không cần pytest)
  run_fuzzing_demo.py    # demo Ch4 + bảng so sánh định lượng
  requirements.txt
  README.md
```

`ch1`–`ch3` có sẵn `__init__.py` nêu rõ việc cần làm (xem docstring trong mỗi package).

Ánh xạ với đề bài:
| Ch | Hướng | Mã C liên quan | Trạng thái |
|---|---|---|---|
| 1 | Kripke + BMC | `src/state_machine.c`, `src/kripke.c`, `test/ch1_kripke.c` | khung Python |
| 2 | Memory safety | `src/auth.c` (lỗi cố ý `-DVULN`) | khung Python |
| 3 | SMT | `src/auth.c` (`off = 12 + i*RECORD_SIZE`) | khung Python |
| 4 | Fuzzing | `src/auth.c` (`auth_store_parse`) + `test/fuzz_store.c` | **hoàn thiện** |

---

# Chương 4 — Fuzzing (black-box vs white-box)

Parser mục tiêu: `auth_store_parse()` (`src/auth.c`) — **magic `"WSAC"` (4 byte) +
version + count + record 88 byte**, đúng đề "parser có magic byte", đồng thời
chứa lỗi *cố ý* để tìm.

## Chạy

ASan **không có** trên MinGW của máy này (thiếu `-lasan`) → chạy dưới **WSL Ubuntu**
(có gcc 15, gcov, ASan, python3, z3):

```bash
wsl -d Ubuntu -e bash -lc "cd /mnt/c/Users/lenovo/Desktop/temp/web_in_c/python && python3 run_fuzzing_demo.py"
wsl -d Ubuntu -e bash -lc "cd /mnt/c/Users/lenovo/Desktop/temp/web_in_c/python && python3 tests/test_ch4_fuzzing.py"
```

(Không cài được `libssl-dev` do sudo cần mật khẩu → dùng **stub OpenSSL**; parser
không hề dùng crypto nên stub không ảnh hưởng kết quả.)

## Ba "oracle"

| Oracle | Cách đo |
|---|---|
| **qua cổng** | input được chấp nhận: tiến trình in `rc=0` (đã qua magic + version) |
| **crash** | mã thoát là signal (Linux) / NTSTATUS (`0xC0000005`...), hoặc stderr có `AddressSanitizer` |
| **coverage** | `gcov` báo `Lines executed:X%` trên `auth.c` (tín hiệu white-box) |

## Kết quả (đo trên WSL, ASan bật)

```
coverage after seeding: 12.16%

[1] BLACK-BOX (random)          found=none    tries=1500   time=39.9s
[2] COVERAGE-GUIDED, NO seeds   found=none    tries=300    time=8.5s
[3] COVERAGE-GUIDED, seeded     found=crash   tries=17     time=0.6s
[4] WHITE-BOX  Z3 gate   54.19 ms  ->  b'WSAC\x01\x00'
    WHITE-BOX  structural gate accepted in 1 try
    WHITE-BOX  11-byte off-by-one  ->  ASan heap-buffer-overflow
```

### Diễn giải
- **Black-box thất bại**: magic 4 byte ⇒ ~2⁻³² (thêm version ~2⁻⁴⁸); không thể "đoán".
- **Coverage-guided KHÔNG seed ≈ black-box**: cổng là **một `memcmp`**, không có nhánh
  theo từng byte ⇒ coverage **không cho gradient** (khác ví dụ `check_magic` 4 nhánh).
- **Coverage-guided CÓ seed**: seed đã "qua cổng", mutation từ đó chỉ 17 lần là chạm lỗi.
- **White-box**: Z3 giải thẳng magic/version (54 ms); dựng input theo cấu trúc thì qua
  cổng trong **1 lần** và bắt lỗi qua ASan.

## Ghi chú kỹ thuật
- Biên dịch **từng file** (`-c`) để `.gcno` đặt tên theo nguồn (`auth.gcno`).
- `.gcda` chỉ ghi khi tiến trình thoát **bình thường**; lần crash (ASan abort) không
  đóng góp coverage.
- Crash oracle mạnh nhất khi có ASan; không ASan thì chỉ lỗi chạm trang nhớ chưa map
  mới crash (vd off-by-one).
- Thư mục `_work` có thể bị **khoá** khi WSL còn giữ handle → `wsl --shutdown` khi cần
  di chuyển/xoá.

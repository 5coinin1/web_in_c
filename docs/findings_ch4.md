# Chương 4 — Fuzzing: black-box vs white-box

> Sinh viên: _điền tên/MSSV_ — Môn: An toàn phần mềm (CSE703093)
> Ngày sinh báo cáo: 2026-10-21 — Nguồn: `results/ch4/`
> Toolchain: WSL Ubuntu, gcc 15.2, ASan/UBSan, gcov, Python 3.14 + Z3

## 1. Mục tiêu và đối tượng

Parser mục tiêu: `auth_store_parse()` (`src/auth.c`) — định dạng account-store:

```
0  4  magic "WSAC"
4  2  version (u16, phải = 1)
6  2  reserved
8  4  count (u32, file-controlled)
12 88 record (username[32] + salt[16] + hash[32] + created_at[8])
```

Đây là parser có **magic byte** đúng yêu cầu Chương 4, đồng thời chứa lỗi cố ý
`-DVULN` (CWE-193/125/787) để làm mục tiêu cho fuzzing.

## 2. Kỹ thuật đã dùng

| Kỹ thuật | Cách hoạt động | Oracle |
|---|---|---|
| Black-box | Random bytes, không phản hồi | Qua magic (`rc=0`) / crash / ASan |
| Coverage-guided, không seed | Sinh input, đo `gcov`, giữ input tăng coverage | Coverage + crash |
| Coverage-guided, có seed | Bắt đầu từ 10 seed cấu trúc đúng | Coverage + crash |
| White-box Z3 | Mã hóa magic/version thành ràng buộc, Z3 giải | Input qua cổng |
| White-box structural | Dựng header/record theo hiểu biết định dạng | Input qua cổng + crash |

Seed corpus: 10 file (rỗng, 4 byte, 6 byte, 12 byte, 100 byte, 188 byte, …).
Coverage sau khi chạy seed: **12.16%**.

## 3. Kết quả định lượng

| Kỹ thuật | Số lần thử | Thời gian | Kết quả | Coverage |
|---|---|---|---|---|
| Black-box (random) | 1500 | 45.7 s | **none** | — |
| Coverage-guided, no seed | 300 | 9.3 s | **none** | — |
| Coverage-guided, seeded | 17 | 0.7 s | **crash** | 12.16% |
| White-box Z3 / structural | 1 lần dựng | 100.75 ms (Z3) | qua cổng + **ASan** | — |

- **Black-box thất bại**: magic 4 byte + version 2 byte ⇒ xác suất ngẫu nhiên
  ~2⁻⁴⁸; 1500 lần thử không đủ.
- **Coverage-guided không seed ≈ black-box**: cổng là một `memcmp`, không có
  nhánh theo từng byte nên coverage không cho "gradient" để tiến gần magic.
- **Coverage-guided có seed**: seed đã qua cổng, mutation từ đó chỉ **17 lần**
  là chạm lỗi — nhanh hơn black-box ~88 lần (theo số lần thử).
- **White-box**: Z3 giải thẳng `WSAC\x01\x00` trong **100.75 ms**;
  structural gate qua cổng trong **1 lần** và bắt lỗi qua ASan.

## 4. Cùng một lỗi được tìm bởi nhiều kỹ thuật

- Coverage-guided seeded (17 lần) và white-box structural (1 lần) đều dẫn tới
  **CWE-193 off-by-one** tại `src/auth.c:122` / `src/bytes.h:30` — cùng lỗi mà
  Chương 2 đã chứng minh bằng ASan.
- Black-box không tìm được trong ngân sách 1500 lần; đây là kết quả **hợp lệ**
  và là bài học về giới hạn của random fuzzing trước magic/checksum.
- Log ASan trong demo: `11-byte off-by-one -> oracle=ASan`.

## 5. Bảng before/after (Chương 4)

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-193 (CWE-125/787 liên quan) | `src/auth.c:122` / `src/bytes.h:30` | Fuzzing tìm crash: 11-byte store → ASan heap-buffer-overflow; seeded 17 lần / white-box 1 lần | Fixed build không crash; parser trả `-1`; fuzzing không tìm thấy crash | Fuzzer + ASan + gcov |
| CWE-248 (nếu có Python target) | `python/ch4_fuzzing` | — | — | (không áp dụng cho parser C này) |

## 6. Test của toolkit

`python3 tests/test_ch4_fuzzing.py` → **5/5 passed**:
- `test_black_box_fails_to_guess_magic`
- `test_coverage_guided_reaches_at_least_seed_coverage`
- `test_structural_crash_triggers_asan`
- `test_structural_gate_is_accepted`
- `test_z3_solves_the_magic`

## 7. Hạn chế

- Đây là fuzzer tự viết (không dùng AFL/libFuzzer); đủ để so sánh định lượng
  black-box vs white-box nhưng không có mutation engine công nghiệp.
- Black-box chỉ chạy 1500 lần; tăng ngân sách không làm thay đổi bản chất
  xác suất ~2⁻⁴⁸.
- Coverage đo trên `auth.c` bằng gcov; không đo nhánh assembly.
- Chỉ một parser mục tiêu; chưa fuzz toàn bộ server/network.
- Trên MinGW không có ASan; số liệu chạy trong WSL Ubuntu.

## 8. Bằng chứng

- `results/ch4/run_fuzzing_demo.txt` — log đầy đủ 4 kỹ thuật.
- `results/ch4/pytest.txt` — log 5/5 test PASS.
- `results/ch4/auth.c.gcov` — coverage chi tiết.
- `results/ch4/summary.txt` — bảng tóm tắt.
- `python/ch4_fuzzing/_work/` — binary, seed, `.gcda/.gcno` (sinh khi chạy).

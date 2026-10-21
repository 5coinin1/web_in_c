# Chương 2 — Kiểm toán an toàn bộ nhớ cho parser account-store

> Sinh viên: _điền tên/MSSV_ — Môn: An toàn phần mềm (CSE703093)
> Ngày sinh báo cáo: 2026-10-21 — Git HEAD: `4cb173f`
> Toolchain: gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0; Python 3.14.4

## 1. Phạm vi và attack surface

Chương trình mục tiêu là server chat C (`src/`). Trong phạm vi Chương 2, đối
tượng kiểm toán là parser nhị phân `auth_store_parse()` trong `src/auth.c` —
hàm đọc file account-store `server_data/accounts.dat`:

```
offset  size  field
0       4     magic "WSAC"
4       2     version (u16, phải = 1)
6       2     reserved
8       4     count (u32, do file điều khiển)
12      88*N  record (username[32] + salt[16] + hash[32] + created_at[8])
```

Attack surface: file `server_data/accounts.dat` (hoặc bất kỳ buffer nào được
đưa vào `auth_store_parse`). Trong repo, `test/fuzz_store.c` là harness đọc file
và gọi parser — dùng để tái hiện lỗi mà không cần chạy server.

Ba lỗ hổng được cấy có chủ đích (ghi rõ trong README của project) để làm
"đối tượng" cho kiểm toán; báo cáo này chứng minh chúng tồn tại bằng ASan và
xác nhận bản vá.

## 2. Quy trình và công cụ

1. **Phân tích tĩnh:** `cppcheck 2.19` (`--enable=all --inconclusive`) trên cả
   hai view `-DVULN` và mặc định; thêm pattern scanner của project
   (`python/ch2_memory_safety/pattern_scan.py`, dựa trên mẫu rule-based của
   `ch2_memsafe/pattern_scanner.py` trong toolkit, bổ sung rule theo ngữ cảnh
   `count`/`off`/`len`) để bắt các mẫu mà cppcheck bỏ sót.
2. **Sinh PoC:** `tools/make_pocs.py` tạo 3 file `poc_count.dat`,
   `poc_short.dat`, `poc_offbyone.dat` (mỗi file nhắm một bug).
3. **Dynamic evidence:** biên dịch `test/fuzz_store.c + src/auth.c + src/log.c`
   với `gcc -fsanitize=address,undefined`, lần lượt `-DVULN` (v0) và mặc định
   (v1); chạy cùng 3 PoC; lưu toàn bộ stdout/stderr.

   ```bash
   gcc -std=gnu11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \
       -DVULN -I src -I python/ch4_fuzzing/stubs \
       test/fuzz_store.c src/auth.c src/log.c \
       python/ch4_fuzzing/stubs/stub_openssl.c -o results/ch2/build/fuzz_store_vuln -pthread
   ```

   Bản vá bỏ `-DVULN` và đổi output thành `fuzz_store_fixed`.

4. **Đối chiếu:** bảng before/after + log ASan + kết quả harness bản vá.

Lệnh chạy lại (trong WSL Ubuntu):

```bash
cd /mnt/c/Users/lenovo/Desktop/temp/web_in_c
python3 python/ch2_memory_safety/run_ch2.py
```

## 3. Tổng hợp kết quả

| ID | CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|---|
| CH2-01 | CWE-193 | `src/auth.c` | dòng 114 (trong nhánh #ifdef VULN) — `poc_offbyone.dat` → ASan | dòng 116 (nhánh mặc định) | ASan + fixed harness |
| CH2-02 | CWE-787 | `src/auth.c` | dòng 122 (count), 129-147 (vòng lặp + ghi) — `poc_count.dat` → ASan | dòng 123-127 (cap count) | ASan + fixed harness |
| CH2-03 | CWE-125 | `src/auth.c` | dòng 130 (off), 142-146 (memcpy/get_i64) — `poc_short.dat` → ASan | dòng 132-136 (kiểm tra off) | ASan + fixed harness |

- **cppcheck (v0):** 11 finding(s): information=1, style=10
  → **0 finding memory-safety**; chỉ có style/information.
- **cppcheck (v1):** 12 finding(s): information=2, style=10 → không có lỗi bộ nhớ.
- **Pattern scanner:** 3 finding — CWE-125=1, CWE-129=1, CWE-193=1.
  Lưu ý: rule `count` gắn CWE-129 (nguyên nhân — thiếu validate index), còn ASan
  xác nhận CWE-787 (hậu quả — ghi quá biên); đây là cùng một lỗ hổng.
- **ASan:** phát hiện đủ 3 lỗi ở bản `-DVULN`; bản vá sạch (0 ASan report).
  `vuln_bugs_found = 3/3`,
  `fixed_clean = 3/3`.

> **Nhận xét quan trọng:** cppcheck **không** phát hiện 3 lỗi biên này (false
> negative) vì chúng phụ thuộc giá trị `count`/`off` do file điều khiển và quan
> hệ giữa `off`, `len`, `MAX_ACCOUNTS` — vượt quá khả năng phân tích cục bộ của
> nó. Vì vậy phải dùng thêm pattern scanner (phát hiện theo ngữ cảnh) và ASan
> (chứng minh động). Đây là bài học phương pháp luận: **static analysis không
> đủ, cần kết hợp nhiều lớp**.

## 4. Chi tiết từng lỗ hổng

### 4.1 CWE-193 — Off-by-one Error tại `src/auth.c`

**Vị trí & mô tả.** `Header length check accepts an 11-byte store`. Dòng lỗi: 114 (trong nhánh #ifdef VULN); bản vá: 116 (nhánh mặc định).

**Nguyên nhân gốc rễ.** Điều kiện `len < 11` chấp nhận buffer 11 byte, nhưng sau đó `get_u32(buf + 8)` đọc 4 byte tại offset 8..11. Buffer 11 byte chỉ có chỉ số hợp lệ 0..10, nên byte thứ 11 bị đọc ra ngoài (off-by-one). Đây là lỗi biên kinh điển: kiểm tra thiếu 1 byte so với kích thước header thật (12 byte: 4 magic + 2 version + 2 reserved + 4 count).

**Bằng chứng lỗi tồn tại (v0 / `-DVULN`).** PoC `poc_offbyone.dat`:

```text
==696==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x79f9fd9e001b at pc 0x5afe7b1952f8 bp 0x7ffc5a373d80 sp 0x7ffc5a373d70
READ of size 1 at 0x79f9fd9e001b thread T0
    #0 0x5afe7b1952f7 in get_u32 /mnt/c/Users/lenovo/Desktop/temp/web_in_c/src/bytes.h:30
    #1 0x5afe7b1952f7 in auth_store_parse /mnt/c/Users/lenovo/Desktop/temp/web_in_c/src/auth.c:122
SUMMARY: AddressSanitizer: heap-buffer-overflow /mnt/c/Users/lenovo/Desktop/temp/web_in_c/src/bytes.h:30 in get_u32
```

Kết quả ASan: `heap-buffer-overflow`, `READ of size 1`,
frame `src/bytes.h:30`. Log đầy đủ: `results/ch2/asan/vuln_poc_offbyone.dat.txt`.

**Cách vá.**

Trước (v0):

```c
#ifdef VULN
    // [BUG C - CWE-193 off-by-one]
    if (!buf || len < 11) return -1;
#else
    if (!buf || len < 12) return -1;
#endif
```

Sau (v1):

```c
// Fixed build: header is 12 bytes.
if (!buf || len < 12) return -1;
```

Đổi biên thành `len < 12` để header 12 byte luôn nằm trong buffer trước khi gọi `get_u32(buf + 8)`. Đây là sửa nguyên nhân gốc rễ (biên của header), không phải che triệu chứng.

**Bằng chứng đã vá (v1).** `fixed: parser rc=-1, accounts=0, không có ASan.` — log:
`results/ch2/asan/fixed_poc_offbyone.dat.txt`.

### 4.2 CWE-787 — Out-of-bounds Write tại `src/auth.c`

**Vị trí & mô tả.** `File-controlled count writes past g_accounts[MAX_ACCOUNTS]`. Dòng lỗi: 122 (count), 129-147 (vòng lặp + ghi); bản vá: 123-127 (cap count).

**Nguyên nhân gốc rễ.** `count` đọc từ file (offset 8) được dùng trực tiếp làm biên vòng lặp và làm chỉ số ghi vào `g_accounts[256]`. Bản `-DVULN` bỏ hoàn toàn kiểm tra `count > MAX_ACCOUNTS`, nên file có count=300 sẽ ghi 300 phần tử vào mảng toàn cục chỉ có 256 slot — ghi quá biên (CWE-787). Lỗi gốc là thiếu validate chỉ số mảng do input điều khiển (CWE-129).

**Bằng chứng lỗi tồn tại (v0 / `-DVULN`).** PoC `poc_count.dat`:

```text
==695==ERROR: AddressSanitizer: global-buffer-overflow on address 0x634a9d2c97a0 at pc 0x634a9d2b76ff bp 0x7ffc5e0e05e0 sp 0x7ffc5e0e05d0
WRITE of size 32 at 0x634a9d2c97a0 thread T0
    #1 0x634a9d2b76fe in auth_store_parse /mnt/c/Users/lenovo/Desktop/temp/web_in_c/src/auth.c:142
0x634a9d2c97a0 is located 32 bytes before global variable 'out' defined in '/mnt/c/Users/lenovo/Desktop/temp/web_in_c/src/log.c:65:17' (0x634a9d2c97c0) of size 256
0x634a9d2c97a0 is located 0 bytes after global variable 'g_accounts' defined in '/mnt/c/Users/lenovo/Desktop/temp/web_in_c/src/auth.c:29:18' (0x634a9d2c3fa0) of size 22528
```

Kết quả ASan: `global-buffer-overflow`, `WRITE of size 32`,
frame `src/auth.c:142`. Log đầy đủ: `results/ch2/asan/vuln_poc_count.dat.txt`.

**Cách vá.**

Trước (v0):

```c
uint32_t count = get_u32(buf + 8);

for (uint32_t i = 0; i < count; i++) {
    ...
    account_t *a = &g_accounts[g_num_accounts];
    memcpy(a->username, buf + off, 32);
    ...
    g_num_accounts++;
}
```

Sau (v1):

```c
uint32_t count = get_u32(buf + 8);
if (count > MAX_ACCOUNTS) count = MAX_ACCOUNTS;

for (uint32_t i = 0; i < count; i++) {
    ...
    g_num_accounts++;
}
```

Cap `count` tại `MAX_ACCOUNTS` trước khi dùng làm biên/chỉ số. Cách này loại bỏ khả năng ghi quá mảng; file quá lớn bị xử lý như bản ghi hợp lệ đầu tiên (xem phần hạn chế: cap thay vì từ chối).

**Bằng chứng đã vá (v1).** `fixed: accounts=256 (cap), không có ASan.` — log:
`results/ch2/asan/fixed_poc_count.dat.txt`.

### 4.3 CWE-125 — Out-of-bounds Read tại `src/auth.c`

**Vị trí & mô tả.** `Record copy does not validate off against len`. Dòng lỗi: 130 (off), 142-146 (memcpy/get_i64); bản vá: 132-136 (kiểm tra off).

**Nguyên nhân gốc rễ.** `off = 12 + (size_t)i * RECORD_SIZE` được tính từ `count`/`i` do file điều khiển nhưng không được so với `len`. Với header count=1 và chỉ 5 byte record, `memcpy(a->username, buf + off, 32)` đọc 32 byte từ vùng heap chỉ có 5 byte — đọc quá biên (CWE-125). Bản vá dùng `RECORD_SIZE > len - off` thay vì `off + RECORD_SIZE <= len` để tránh tràn số khi cộng.

**Bằng chứng lỗi tồn tại (v0 / `-DVULN`).** PoC `poc_short.dat`:

```text
==697==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x7b6d537e004c at pc 0x62020feef6f1 bp 0x7fffd7bb0350 sp 0x7fffd7bb0340
READ of size 32 at 0x7b6d537e004c thread T0
    #1 0x62020feef6f0 in auth_store_parse /mnt/c/Users/lenovo/Desktop/temp/web_in_c/src/auth.c:142
```

Kết quả ASan: `heap-buffer-overflow`, `READ of size 32`,
frame `src/auth.c:142`. Log đầy đủ: `results/ch2/asan/vuln_poc_short.dat.txt`.

**Cách vá.**

Trước (v0):

```c
size_t off = 12 + (size_t)i * RECORD_SIZE;
account_t *a = &g_accounts[g_num_accounts];
memcpy(a->username, buf + off, 32);
memcpy(a->salt, buf + off + 32, SALT_LEN);
memcpy(a->hash, buf + off + 32 + SALT_LEN, HASH_LEN);
a->created_at = get_i64(buf + off + 32 + SALT_LEN + HASH_LEN);
```

Sau (v1):

```c
size_t off = 12 + (size_t)i * RECORD_SIZE;

// Overflow-safe: subtraction cannot wrap.
if (off > len || RECORD_SIZE > len - off) break;

account_t *a = &g_accounts[g_num_accounts];
memcpy(a->username, buf + off, 32);
```

Kiểm tra `off <= len` và `RECORD_SIZE <= len - off` trước mọi lần đọc. Dùng phép trừ để tránh `off + RECORD_SIZE` bị wrap (CWE-190) trên 32-bit hoặc với count rất lớn.

**Bằng chứng đã vá (v1).** `fixed: accounts=0 (break ở bản ghi đầu), không có ASan.` — log:
`results/ch2/asan/fixed_poc_short.dat.txt`.


## 5. Bảng before/after (Phần 5 của báo cáo)

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-193 | `src/auth.c:114` | 11-byte store được chấp nhận; ASan `heap-buffer-overflow` READ size 1 tại `src/bytes.h:30` (caller `src/auth.c:122`) | `len < 12`; parser trả `-1`, không ASan | ASan/UBSan + harness |
| CWE-787 | `src/auth.c:122-147` | `count=300` ghi quá `g_accounts[256]`; ASan `global-buffer-overflow` WRITE size 32 tại `src/auth.c:142` | `count` cap tại `MAX_ACCOUNTS`; `accounts=256`, không ASan | ASan/UBSan + harness |
| CWE-125 | `src/auth.c:130-146` | record ngắn bị đọc quá heap; ASan `heap-buffer-overflow` READ size 32 tại `src/auth.c:142` | kiểm tra `off > len` / `RECORD_SIZE > len - off`; `accounts=0`, không ASan | ASan/UBSan + harness |

## 6. Hạn chế

- Đây là các lỗi **cấy có chủ đích** trong một parser nhỏ; kết quả không đại
  diện cho toàn bộ server.
- Bản vá CWE-787 **cap** `count` tại 256 thay vì từ chối file sai. Về mặt an
  toàn bộ nhớ là đúng, nhưng về mặt nghiệp vụ nên cân nhắc trả lỗi
  (`return -1`) thay vì im lặng cắt bớt dữ liệu.
- ASan/UBSan không có trên MinGW; số liệu trong báo cáo chạy trên WSL Ubuntu
  (gcc 15.2). Trên Windows cần chạy lại trong WSL.
- Pattern scanner là rule-based, chỉ nhắm `auth.c`; không thay thế SAST đầy đủ.
- Chưa chạy Valgrind (chưa cài trong WSL); ASan đã đủ chứng minh 3 lỗi.

## 7. Lệnh tái hiện

```bash
# 1) Toàn bộ Chương 2 (static + ASan + report)
wsl -d Ubuntu -e bash -lc 'cd /mnt/c/Users/lenovo/Desktop/temp/web_in_c && python3 python/ch2_memory_safety/run_ch2.py'

# 2) Chỉ static analysis
wsl -d Ubuntu -e bash -lc 'cd /mnt/c/Users/lenovo/Desktop/temp/web_in_c && python3 python/ch2_memory_safety/static_check.py'

# 3) Chỉ ASan
wsl -d Ubuntu -e bash -lc 'cd /mnt/c/Users/lenovo/Desktop/temp/web_in_c && python3 python/ch2_memory_safety/asan_runner.py'
```

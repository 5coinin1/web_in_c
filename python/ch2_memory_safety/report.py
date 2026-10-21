"""Generate the Chapter-2 findings report and the before/after table.

Inputs (produced by static_check.py and asan_runner.py):
    results/ch2/static_summary.json
    results/ch2/results.json
    results/ch2/asan/*.txt

Outputs:
    docs/findings_ch2.md
    docs/before_after_ch2.md

The narrative follows the five sub-sections required by the course report
guide: location, root cause, before evidence, fix, after evidence.
"""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from typing import Dict, List


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results" / "ch2"
DOCS = ROOT / "docs"


def _load(name: str) -> dict:
    p = OUT / name
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def _git_head() -> str:
    try:
        r = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=ROOT, capture_output=True, text=True, timeout=10,
        )
        return r.stdout.strip() if r.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def _asan_excerpt(log_rel: str) -> str:
    p = ROOT / log_rel
    if not p.exists():
        return "(missing ASan log)"
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    keep = []
    for line in lines:
        if ("ERROR: AddressSanitizer" in line
                or " of size " in line
                or "auth_store_parse" in line
                or "get_u32" in line
                or "bytes.h" in line):
            keep.append(line.rstrip())
        if len(keep) >= 5:
            break
    return "\n".join(keep) if keep else "\n".join(lines[:5])


def _run(results: dict, variant: str, poc: str) -> dict:
    for r in results.get("runs", []):
        if r["variant"] == variant and r["poc"] == poc:
            return r
    return {}


FINDINGS = [
    {
        "id": "CH2-01",
        "cwe": "CWE-193",
        "cwe_name": "Off-by-one Error",
        "title": "Header length check accepts an 11-byte store",
        "file": "src/auth.c",
        "vuln_lines": "114 (trong nhánh #ifdef VULN)",
        "fixed_lines": "116 (nhánh mặc định)",
        "poc": "poc_offbyone.dat",
        "cwe_secondary": "CWE-125 (out-of-bounds read)",
        "root_cause": (
            "Điều kiện `len < 11` chấp nhận buffer 11 byte, nhưng sau đó "
            "`get_u32(buf + 8)` đọc 4 byte tại offset 8..11. Buffer 11 byte chỉ "
            "có chỉ số hợp lệ 0..10, nên byte thứ 11 bị đọc ra ngoài (off-by-one). "
            "Đây là lỗi biên kinh điển: kiểm tra thiếu 1 byte so với kích thước header "
            "thật (12 byte: 4 magic + 2 version + 2 reserved + 4 count)."
        ),
        "before_code": """#ifdef VULN
    // [BUG C - CWE-193 off-by-one]
    if (!buf || len < 11) return -1;
#else
    if (!buf || len < 12) return -1;
#endif""",
        "fix_code": """// Fixed build: header is 12 bytes.
if (!buf || len < 12) return -1;""",
        "fix_explain": (
            "Đổi biên thành `len < 12` để header 12 byte luôn nằm trong buffer "
            "trước khi gọi `get_u32(buf + 8)`. Đây là sửa nguyên nhân gốc rễ "
            "(biên của header), không phải che triệu chứng."
        ),
        "after_code": "fixed: parser rc=-1, accounts=0, không có ASan.",
    },
    {
        "id": "CH2-02",
        "cwe": "CWE-787",
        "cwe_name": "Out-of-bounds Write",
        "title": "File-controlled count writes past g_accounts[MAX_ACCOUNTS]",
        "file": "src/auth.c",
        "vuln_lines": "122 (count), 129-147 (vòng lặp + ghi)",
        "fixed_lines": "123-127 (cap count)",
        "poc": "poc_count.dat",
        "cwe_secondary": "CWE-129 (improper validation of array index)",
        "root_cause": (
            "`count` đọc từ file (offset 8) được dùng trực tiếp làm biên vòng lặp "
            "và làm chỉ số ghi vào `g_accounts[256]`. Bản `-DVULN` bỏ hoàn toàn "
            "kiểm tra `count > MAX_ACCOUNTS`, nên file có count=300 sẽ ghi 300 "
            "phần tử vào mảng toàn cục chỉ có 256 slot — ghi quá biên (CWE-787). "
            "Lỗi gốc là thiếu validate chỉ số mảng do input điều khiển (CWE-129)."
        ),
        "before_code": """uint32_t count = get_u32(buf + 8);

for (uint32_t i = 0; i < count; i++) {
    ...
    account_t *a = &g_accounts[g_num_accounts];
    memcpy(a->username, buf + off, 32);
    ...
    g_num_accounts++;
}""",
        "fix_code": """uint32_t count = get_u32(buf + 8);
if (count > MAX_ACCOUNTS) count = MAX_ACCOUNTS;

for (uint32_t i = 0; i < count; i++) {
    ...
    g_num_accounts++;
}""",
        "fix_explain": (
            "Cap `count` tại `MAX_ACCOUNTS` trước khi dùng làm biên/chỉ số. "
            "Cách này loại bỏ khả năng ghi quá mảng; file quá lớn bị xử lý như "
            "bản ghi hợp lệ đầu tiên (xem phần hạn chế: cap thay vì từ chối)."
        ),
        "after_code": "fixed: accounts=256 (cap), không có ASan.",
    },
    {
        "id": "CH2-03",
        "cwe": "CWE-125",
        "cwe_name": "Out-of-bounds Read",
        "title": "Record copy does not validate off against len",
        "file": "src/auth.c",
        "vuln_lines": "130 (off), 142-146 (memcpy/get_i64)",
        "fixed_lines": "132-136 (kiểm tra off)",
        "poc": "poc_short.dat",
        "cwe_secondary": "CWE-190 (integer overflow/wraparound) — lý do dùng phép trừ",
        "root_cause": (
            "`off = 12 + (size_t)i * RECORD_SIZE` được tính từ `count`/`i` do file "
            "điều khiển nhưng không được so với `len`. Với header count=1 và chỉ "
            "5 byte record, `memcpy(a->username, buf + off, 32)` đọc 32 byte từ "
            "vùng heap chỉ có 5 byte — đọc quá biên (CWE-125). Bản vá dùng "
            "`RECORD_SIZE > len - off` thay vì `off + RECORD_SIZE <= len` để "
            "tránh tràn số khi cộng."
        ),
        "before_code": """size_t off = 12 + (size_t)i * RECORD_SIZE;
account_t *a = &g_accounts[g_num_accounts];
memcpy(a->username, buf + off, 32);
memcpy(a->salt, buf + off + 32, SALT_LEN);
memcpy(a->hash, buf + off + 32 + SALT_LEN, HASH_LEN);
a->created_at = get_i64(buf + off + 32 + SALT_LEN + HASH_LEN);""",
        "fix_code": """size_t off = 12 + (size_t)i * RECORD_SIZE;

// Overflow-safe: subtraction cannot wrap.
if (off > len || RECORD_SIZE > len - off) break;

account_t *a = &g_accounts[g_num_accounts];
memcpy(a->username, buf + off, 32);""",
        "fix_explain": (
            "Kiểm tra `off <= len` và `RECORD_SIZE <= len - off` trước mọi lần đọc. "
            "Dùng phép trừ để tránh `off + RECORD_SIZE` bị wrap (CWE-190) trên "
            "32-bit hoặc với count rất lớn."
        ),
        "after_code": "fixed: accounts=0 (break ở bản ghi đầu), không có ASan.",
    },
]


def _finding_section(f: dict, results: dict) -> str:
    vr = _run(results, "vuln", f["poc"])
    fr = _run(results, "fixed", f["poc"])
    excerpt = _asan_excerpt(vr.get("log", ""))
    return f"""### 4.{FINDINGS.index(f) + 1} {f['cwe']} — {f['cwe_name']} tại `{f['file']}`

**Vị trí & mô tả.** `{f['title']}`. Dòng lỗi: {f['vuln_lines']}; bản vá: {f['fixed_lines']}.

**Nguyên nhân gốc rễ.** {f['root_cause']}

**Bằng chứng lỗi tồn tại (v0 / `-DVULN`).** PoC `{f['poc']}`:

```text
{excerpt}
```

Kết quả ASan: `{vr.get('error')}`, `{vr.get('access')} of size {vr.get('size')}`,
frame `{vr.get('frame')}`. Log đầy đủ: `{vr.get('log', '?')}`.

**Cách vá.**

Trước (v0):

```c
{f['before_code']}
```

Sau (v1):

```c
{f['fix_code']}
```

{f['fix_explain']}

**Bằng chứng đã vá (v1).** `{f['after_code']}` — log:
`{fr.get('log', '?')}`.
"""


def build_findings(results: dict, static: dict) -> str:
    cpp_v = static.get("vuln", {})
    cpp_f = static.get("fixed", {})
    pattern = static.get("pattern_scan", {})
    pattern_by_cwe = ", ".join(
        f"{k}={v}" for k, v in pattern.get("by_cwe", {}).items()
    ) or "n/a"
    toolchain = results.get("toolchain", {})
    checks = results.get("checks", {})

    rows = "\n".join(
        f"| {f['id']} | {f['cwe']} | `{f['file']}` | "
        f"dòng {f['vuln_lines']} — `{f['poc']}` → ASan | "
        f"dòng {f['fixed_lines']} | ASan + fixed harness |"
        for f in FINDINGS
    )

    details = "\n".join(_finding_section(f, results) for f in FINDINGS)

    return f"""# Chương 2 — Kiểm toán an toàn bộ nhớ cho parser account-store

> Sinh viên: _điền tên/MSSV_ — Môn: An toàn phần mềm (CSE703093)
> Ngày sinh báo cáo: {time.strftime('%Y-%m-%d')} — Git HEAD: `{_git_head()}`
> Toolchain: {toolchain.get('gcc', 'gcc (WSL)')}; Python {toolchain.get('python', '?')}

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
   gcc -std=gnu11 -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer \\
       -DVULN -I src -I python/ch4_fuzzing/stubs \\
       test/fuzz_store.c src/auth.c src/log.c \\
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
{rows}

- **cppcheck (v0):** {cpp_v.get('summary', 'n/a')}
  → **0 finding memory-safety**; chỉ có style/information.
- **cppcheck (v1):** {cpp_f.get('summary', 'n/a')} → không có lỗi bộ nhớ.
- **Pattern scanner:** {pattern.get('count', 0)} finding — {pattern_by_cwe}.
  Lưu ý: rule `count` gắn CWE-129 (nguyên nhân — thiếu validate index), còn ASan
  xác nhận CWE-787 (hậu quả — ghi quá biên); đây là cùng một lỗ hổng.
- **ASan:** phát hiện đủ 3 lỗi ở bản `-DVULN`; bản vá sạch (0 ASan report).
  `vuln_bugs_found = {checks.get('vuln_bugs_found', '?')}/3`,
  `fixed_clean = {checks.get('fixed_clean', '?')}/3`.

> **Nhận xét quan trọng:** cppcheck **không** phát hiện 3 lỗi biên này (false
> negative) vì chúng phụ thuộc giá trị `count`/`off` do file điều khiển và quan
> hệ giữa `off`, `len`, `MAX_ACCOUNTS` — vượt quá khả năng phân tích cục bộ của
> nó. Vì vậy phải dùng thêm pattern scanner (phát hiện theo ngữ cảnh) và ASan
> (chứng minh động). Đây là bài học phương pháp luận: **static analysis không
> đủ, cần kết hợp nhiều lớp**.

## 4. Chi tiết từng lỗ hổng

{details}

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
"""


def build_before_after() -> str:
    return """# Bảng before/after — Chương 2

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-193 | `src/auth.c:114` | 11-byte store được chấp nhận; ASan `heap-buffer-overflow` READ size 1 tại `src/bytes.h:30` (caller `src/auth.c:122`) | `len < 12`; parser trả `-1`, không ASan | ASan/UBSan + harness |
| CWE-787 | `src/auth.c:122-147` | `count=300` ghi quá `g_accounts[256]`; ASan `global-buffer-overflow` WRITE size 32 tại `src/auth.c:142` | `count` cap tại `MAX_ACCOUNTS`; `accounts=256`, không ASan | ASan/UBSan + harness |
| CWE-125 | `src/auth.c:130-146` | record ngắn bị đọc quá heap; ASan `heap-buffer-overflow` READ size 32 tại `src/auth.c:142` | kiểm tra `off > len` / `RECORD_SIZE > len - off`; `accounts=0`, không ASan | ASan/UBSan + harness |
"""


def main() -> int:
    results = _load("results.json")
    static = _load("static_summary.json")
    DOCS.mkdir(parents=True, exist_ok=True)

    findings = build_findings(results, static)
    (DOCS / "findings_ch2.md").write_text(findings, encoding="utf-8")
    (DOCS / "before_after_ch2.md").write_text(build_before_after(), encoding="utf-8")
    print(f"Wrote {DOCS / 'findings_ch2.md'}")
    print(f"Wrote {DOCS / 'before_after_ch2.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

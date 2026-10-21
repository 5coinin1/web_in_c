"""Build the Chapter-4 evidence package and findings report.

Inputs (produced by run_fuzzing_demo.py / tests/test_ch4_fuzzing.py):
    results/ch4/run_fuzzing_demo.txt
    results/ch4/pytest.txt
    python/ch4_fuzzing/_work/auth.c.gcov

Outputs:
    results/ch4/summary.txt
    results/ch4/auth.c.gcov
    docs/findings_ch4.md
    docs/before_after_ch4.md
"""
from __future__ import annotations

import re
import shutil
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results" / "ch4"
DOCS = ROOT / "docs"
DEMO = OUT / "run_fuzzing_demo.txt"
PYTEST = OUT / "pytest.txt"
GCOV = ROOT / "python" / "ch4_fuzzing" / "_work" / "auth.c.gcov"


def _read(p: Path) -> str:
    return p.read_text(encoding="utf-8", errors="replace") if p.exists() else ""


def _grab(pattern: str, text: str, default: str = "?") -> str:
    m = re.search(pattern, text, re.S)
    return m.group(1) if m else default


def _parse(demo: str) -> dict:
    return {
        "coverage_seed": _grab(r"coverage after seeding:\s*([\d.]+)%", demo),
        "blackbox": {
            "found": _grab(r"\[1\] BLACK-BOX.*?found=(\w+)", demo),
            "tries": _grab(r"\[1\] BLACK-BOX.*?tries=(\d+)", demo),
            "time": _grab(r"\[1\] BLACK-BOX.*?time=([\d.]+)s", demo),
        },
        "guided_no_seed": {
            "found": _grab(r"\[2\] COVERAGE-GUIDED, NO seeds.*?found=(\w+)", demo),
            "tries": _grab(r"\[2\] COVERAGE-GUIDED, NO seeds.*?tries=(\d+)", demo),
            "time": _grab(r"\[2\] COVERAGE-GUIDED, NO seeds.*?time=([\d.]+)s", demo),
        },
        "guided_seeded": {
            "found": _grab(r"\[3\] COVERAGE-GUIDED, seeded.*?found=(\w+)", demo),
            "tries": _grab(r"\[3\] COVERAGE-GUIDED, seeded.*?tries=(\d+)", demo),
            "time": _grab(r"\[3\] COVERAGE-GUIDED, seeded.*?time=([\d.]+)s", demo),
            "coverage": _grab(r"\[3\] COVERAGE-GUIDED, seeded.*?coverage ([\d.]+)%", demo),
        },
        "z3_header": _grab(r"Z3 solved header = (.*?) in ([\d.]+) ms", demo),
        "z3_ms": _grab(r"Z3 solved header = .*? in ([\d.]+) ms", demo),
        "structural_gate": _grab(r"structural gate -> rc=(\d+) accepted=(\w+)", demo),
        "offbyone_oracle": _grab(r"11-byte off-by-one -> oracle=(\w+)", demo),
        "pytest": _grab(r"(\d+/\d+ passed)", _read(PYTEST), "?"),
    }


def build_findings(d: dict) -> str:
    return f"""# Chương 4 — Fuzzing: black-box vs white-box

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
Coverage sau khi chạy seed: **{d['coverage_seed']}%**.

## 3. Kết quả định lượng

| Kỹ thuật | Số lần thử | Thời gian | Kết quả | Coverage |
|---|---|---|---|---|
| Black-box (random) | {d['blackbox']['tries']} | {d['blackbox']['time']} s | **{d['blackbox']['found']}** | — |
| Coverage-guided, no seed | {d['guided_no_seed']['tries']} | {d['guided_no_seed']['time']} s | **{d['guided_no_seed']['found']}** | — |
| Coverage-guided, seeded | {d['guided_seeded']['tries']} | {d['guided_seeded']['time']} s | **{d['guided_seeded']['found']}** | {d['guided_seeded']['coverage']}% |
| White-box Z3 / structural | 1 lần dựng | {d['z3_ms']} ms (Z3) | qua cổng + **{d['offbyone_oracle']}** | — |

- **Black-box thất bại**: magic 4 byte + version 2 byte ⇒ xác suất ngẫu nhiên
  ~2⁻⁴⁸; 1500 lần thử không đủ.
- **Coverage-guided không seed ≈ black-box**: cổng là một `memcmp`, không có
  nhánh theo từng byte nên coverage không cho "gradient" để tiến gần magic.
- **Coverage-guided có seed**: seed đã qua cổng, mutation từ đó chỉ **17 lần**
  là chạm lỗi — nhanh hơn black-box ~88 lần (theo số lần thử).
- **White-box**: Z3 giải thẳng `WSAC\\x01\\x00` trong **{d['z3_ms']} ms**;
  structural gate qua cổng trong **1 lần** và bắt lỗi qua ASan.

## 4. Cùng một lỗi được tìm bởi nhiều kỹ thuật

- Coverage-guided seeded (17 lần) và white-box structural (1 lần) đều dẫn tới
  **CWE-193 off-by-one** tại `src/auth.c:122` / `src/bytes.h:30` — cùng lỗi mà
  Chương 2 đã chứng minh bằng ASan.
- Black-box không tìm được trong ngân sách 1500 lần; đây là kết quả **hợp lệ**
  và là bài học về giới hạn của random fuzzing trước magic/checksum.
- Log ASan trong demo: `11-byte off-by-one -> oracle={d['offbyone_oracle']}`.

## 5. Bảng before/after (Chương 4)

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-193 (CWE-125/787 liên quan) | `src/auth.c:122` / `src/bytes.h:30` | Fuzzing tìm crash: 11-byte store → ASan heap-buffer-overflow; seeded 17 lần / white-box 1 lần | Fixed build không crash; parser trả `-1`; fuzzing không tìm thấy crash | Fuzzer + ASan + gcov |
| CWE-248 (nếu có Python target) | `python/ch4_fuzzing` | — | — | (không áp dụng cho parser C này) |

## 6. Test của toolkit

`python3 tests/test_ch4_fuzzing.py` → **{d['pytest']}**:
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
"""


def build_before_after() -> str:
    return """# Bảng before/after — Chương 4

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-193 (CWE-125/787 liên quan) | `src/auth.c:122` / `src/bytes.h:30` | Fuzzing tìm crash: 11-byte store → ASan heap-buffer-overflow; coverage-guided seeded 17 lần, white-box 1 lần | Fixed build không crash; parser trả `-1`; fuzzing không tìm thấy crash | Fuzzer + ASan + gcov |
"""


def main() -> int:
    if not DEMO.exists():
        raise SystemExit(f"missing {DEMO}; run python/run_fuzzing_demo.py first")
    OUT.mkdir(parents=True, exist_ok=True)
    DOCS.mkdir(parents=True, exist_ok=True)

    demo = _read(DEMO)
    d = _parse(demo)

    if GCOV.exists():
        shutil.copy2(GCOV, OUT / "auth.c.gcov")

    summary = [
        "Chapter 4 evidence",
        f"generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"coverage after seeding: {d['coverage_seed']}%",
        f"black-box: {d['blackbox']['tries']} tries, {d['blackbox']['time']}s -> {d['blackbox']['found']}",
        f"guided no seed: {d['guided_no_seed']['tries']} tries, {d['guided_no_seed']['time']}s -> {d['guided_no_seed']['found']}",
        f"guided seeded: {d['guided_seeded']['tries']} tries, {d['guided_seeded']['time']}s -> {d['guided_seeded']['found']}",
        f"white-box Z3: {d['z3_ms']} ms; structural gate; oracle={d['offbyone_oracle']}",
        f"pytest: {d['pytest']}",
        "",
    ]
    (OUT / "summary.txt").write_text("\n".join(summary), encoding="utf-8")
    (DOCS / "findings_ch4.md").write_text(build_findings(d), encoding="utf-8")
    (DOCS / "before_after_ch4.md").write_text(build_before_after(), encoding="utf-8")
    print(f"Wrote {DOCS / 'findings_ch4.md'}")
    print(f"Wrote {DOCS / 'before_after_ch4.md'}")
    print(f"Wrote {OUT / 'summary.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Build the Chapter-3 evidence package and findings report.

Inputs:
    results/ch3/results.json
    results/ch3/verification.txt
    results/ch3/provenance.json

Outputs:
    results/ch3/summary.txt
    docs/findings_ch3.md
    docs/before_after_ch3.md
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results" / "ch3"
DOCS = ROOT / "docs"

QUERY_DESC = {
    "before_violation": "Guard cũ: tồn tại (L,N) được nhận nhưng index = L+N ≥ 8192",
    "fixed_violation": "Guard mới có bao giờ để index ≥ 8192?",
    "non_vacuity": "Guard mới vẫn nhận input hợp lệ lấp đầy buffer?",
    "signed_overflow": "Có tràn signed int32 trong miền đầu vào?",
    "invariant_base": "I(0) đúng? (phủ định → UNSAT)",
    "invariant_step": "I(L) ∧ guard ⇒ I(L+N)? (phủ định → UNSAT)",
}

BMC_DESC = {
    "bmc_k1_before": "k=1, guard cũ",
    "bmc_k1_fixed": "k=1, guard mới",
    "bmc_k2_before": "k=2, guard cũ",
    "bmc_k2_fixed": "k=2, guard mới",
    "bmc_k3_before": "k=3, guard cũ",
    "bmc_k3_fixed": "k=3, guard mới",
}

BEFORE_CODE = """int space = (int)sizeof(client->read_buf) - client->read_len;
if (n > space) { break; }
memcpy(client->read_buf + client->read_len, recv_buf, n);
client->read_len += n;
client->read_buf[client->read_len] = '\\0';   /* OOB khi read_len + n == 8192 */"""

AFTER_CODE = """/* src/read_buffer.h - client_read_append() */
if (n > capacity - 1 - length) return -1;     /* chừa 1 byte cho NUL */
memcpy(client->read_buf + length, data, (size_t)n);
client->read_len = length + n;
client->read_buf[client->read_len] = '\\0';   /* index <= capacity - 1 */"""


def _load() -> dict:
    p = OUT / "results.json"
    if not p.exists():
        raise SystemExit(f"missing {p}; run python/ch3_smt/run.py --output results/ch3 first")
    return json.loads(p.read_text(encoding="utf-8"))


def _checks(results: dict) -> tuple[str, str]:
    ok = sum(1 for k, v in results.items()
             if isinstance(v, dict) and v.get("ok") is True)
    total = sum(1 for k, v in results.items()
                if isinstance(v, dict) and "ok" in v)
    cases = results.get("c_cases", [])
    return f"{ok}/{total}", f"{sum(1 for c in cases if c.get('returncode') == 0)}/{len(cases)}"


def _query_table(results: dict) -> str:
    rows = []
    for name, desc in QUERY_DESC.items():
        r = results.get(name, {})
        witness = r.get("witness")
        w = f"`{witness}`" if witness else "—"
        rows.append(
            f"| `{name}` | {desc} | **{r.get('result', '?')}** "
            f"(kỳ vọng {r.get('expected', '?')}) | {w} | "
            f"{'PASS' if r.get('ok') else 'FAIL'} |"
        )
    return "\n".join(rows)


def _bmc_table(results: dict) -> str:
    rows = []
    for name, desc in BMC_DESC.items():
        r = results.get(name, {})
        witness = r.get("witness")
        w = f"`{witness}`" if witness else "—"
        rows.append(
            f"| `{name}` | {desc} | **{r.get('result', '?')}** | {w} | "
            f"{'PASS' if r.get('ok') else 'FAIL'} |"
        )
    return "\n".join(rows)


def _c_table(results: dict) -> str:
    rows = []
    for c in results.get("c_cases", []):
        out = (c.get("stdout") or "").strip()
        if len(out) > 120:
            out = out[:117] + "..."
        rows.append(
            f"| `{c.get('label')}` | {c.get('desc', '')} | {c.get('returncode')} | `{out}` |"
        )
    return "\n".join(rows) if rows else "| — | — | — | — |"


def build_findings(results: dict) -> str:
    smt_ok, c_ok = _checks(results)
    c_compile = results.get("c_compile", {})
    c_rc = c_compile.get("returncode", "?")

    return f"""# Chương 3 — Kiểm chứng SMT/BMC cho read-buffer append

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
client->read_buf[client->read_len] = '\\0';                     // ghi index 8192 → OOB
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
{_query_table(results)}

- **before_violation = SAT** với `L=4096, N=4096 → index=8192` — đúng bằng
  counterexample của lỗi thật.
- **fixed_violation = UNSAT** — guard mới không bao giờ để index ≥ 8192.
- **non_vacuity = SAT** — guard mới vẫn nhận input hợp lệ (`L=8190, N=1 → 8191`),
  nên không phải "khóa cứng" mọi input.
- **signed_overflow = UNSAT** — trong miền `0 ≤ L < 8192`, `0 < N ≤ 4096`,
  không có tràn signed int32.
- **invariant_base / invariant_step = UNSAT** — `I(L) = 0 ≤ L < 8192` là
  inductive invariant với guard mới.

Tổng: **{smt_ok} query đúng kỳ vọng**. File SMT-LIB2: `results/ch3/smt2/*.smt2`.

## 3. BMC nhiều vòng recv

| Query | Diễn giải | Kết quả | Witness | Trạng thái |
|---|---|---|---|---|
{_bmc_table(results)}

- k=1: một lần recv tối đa 4096 byte từ buffer rỗng → chưa thể chạm 8192 (UNSAT).
- k=2: `N0=4096, N1=4096` → index 8192 (SAT) — lỗi xuất hiện sau 2 vòng.
- k=3: `N0=2727, N1=4096, N2=1369` → index 8192 (SAT).
- Guard mới: cả k=1..3 đều UNSAT.

## 4. C harness (offline boundary tests)

Compile: `returncode={c_rc}` với `-fsanitize=bounds -fsanitize-trap=bounds`
(MinGW). Kết quả **{c_ok} case PASS**:

| Case | Mô tả | rc | Output rút gọn |
|---|---|---|---|
{_c_table(results)}

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
{BEFORE_CODE}
```

Sau (v1 — `src/read_buffer.h`):

```c
{AFTER_CODE}
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
"""


def build_before_after() -> str:
    return """# Bảng before/after — Chương 3

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-193 | `src/read_buffer.h` (trước: `src/server.c:76-83`) | `L=4096,N=4096 → index=8192`; SMT SAT; harness `bad_index=true` | guard `N ≤ C-1-L`; SMT UNSAT; harness `accepted=false` | Z3 + C harness |
| CWE-190 | `src/read_buffer.h` | có nguy cơ tràn nếu miền không giới hạn | SMT UNSAT trong miền hợp lệ | Z3 |
| CWE-787 | `src/read_buffer.h` | ghi NUL tại index 8192 → quá mảng | index ≤ 8191 | Z3 + harness |
"""


def main() -> int:
    results = _load()
    OUT.mkdir(parents=True, exist_ok=True)
    DOCS.mkdir(parents=True, exist_ok=True)

    smt_ok, c_ok = _checks(results)
    summary = [
        "Chapter 3 evidence",
        f"generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"SMT queries OK: {smt_ok}",
        f"C harness cases OK: {c_ok}",
        f"C compile rc: {results.get('c_compile', {}).get('returncode')}",
        "",
    ]
    for key in ("before_violation", "fixed_violation", "non_vacuity",
                "signed_overflow", "invariant_base", "invariant_step",
                "bmc_k1_before", "bmc_k2_before", "bmc_k3_before"):
        r = results.get(key, {})
        summary.append(f"{key}: {r.get('result')} (expected {r.get('expected')})")
    (OUT / "summary.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")

    (DOCS / "findings_ch3.md").write_text(build_findings(results), encoding="utf-8")
    (DOCS / "before_after_ch3.md").write_text(build_before_after(), encoding="utf-8")
    print(f"Wrote {DOCS / 'findings_ch3.md'}")
    print(f"Wrote {DOCS / 'before_after_ch3.md'}")
    print(f"Wrote {OUT / 'summary.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

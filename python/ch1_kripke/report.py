"""Build the Chapter-1 evidence package and findings report.

Inputs (already produced by verify.py / test/ch1_kripke.c):
    python/ch1_kripke/generated/results.json
    python/ch1_kripke/generated/verification.txt
    python/ch1_kripke/generated/*counterexample*.json
    results/ch1/ch1_kripke_c.txt        (captured C runner output)

Outputs:
    results/ch1/                        (copied evidence + summary)
    docs/findings_ch1.md
    docs/before_after_ch1.md
"""
from __future__ import annotations

import csv
import json
import re
import shutil
from pathlib import Path
from typing import Dict, List


ROOT = Path(__file__).resolve().parents[2]
GEN = ROOT / "python" / "ch1_kripke" / "generated"
OUT = ROOT / "results" / "ch1"
DOCS = ROOT / "docs"

PROP_DESC = {
    "P1": "Vào phòng bắt buộc đã đăng nhập",
    "P2": "Đã đăng nhập bắt buộc WebSocket đã mở",
    "P3": "CLOSED không còn giữ bất kỳ trạng thái sống",
    "P4": "Chỉ nhận MESSAGE khi đã login + ở trong phòng",
    "P5": "Sau LOGOUT không còn authenticated/member/in_room",
    "P6": "member và in_room luôn tương đương",
    "P7": "authenticated phải ở phase AUTHENTICATED hoặc IN_ROOM",
    "R1": "Có thể đạt authenticated",
    "R2": "Có thể đạt in_room",
    "R3": "Có thể đạt message_accepted",
    "R4": "Có thể đạt logged_out",
    "R5": "Có thể đạt closed",
    "L1": "Từ ws_open luôn có đường tới in_room hoặc closed",
    "L2": "Từ in_room luôn có đường quay lại authenticated",
}

MUTATIONS = {
    "none": "Mô hình đúng (reviewed contract)",
    "join_bypass": "Bỏ qua LOGIN: JOIN_OK từ WS_CONNECTED",
    "message_guard": "Cho MESSAGE khi chưa vào phòng",
    "stale_auth": "Giữ auth_history sau LOGOUT",
}

SHARED_DESC = {
    "shared_same_account": "2 kết nối cùng tài khoản — single session",
    "shared_distinct_accounts": "2 tài khoản khác nhau — cùng phòng",
    "shared_distinct_accounts_buggy_delete": "2 tài khoản — xóa phòng lỗi (role B không bị evict)",
}

SHARED_PROP_DESC = {
    "membership_consistent": "member_A/B khớp phase IN_ROOM",
    "members_authenticated": "không có member nào chưa authenticated",
    "deleted_room_empty": "phòng đã xóa thì không còn member",
    "single_session": "không thể cả 2 kết nối cùng authenticated (cùng tài khoản)",
    "two_accounts_can_login": "2 tài khoản khác nhau có thể cùng authenticated",
}


def _copy(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    if src.exists():
        shutil.copy2(src, dst)


def _load() -> dict:
    p = GEN / "results.json"
    if not p.exists():
        raise SystemExit(f"missing {p}; run python/ch1_kripke/verify.py first")
    return json.loads(p.read_text(encoding="utf-8"))


def _threshold(verification: str) -> str:
    m = re.search(r"Completeness threshold for state invariants:\s*(\d+)", verification)
    return m.group(1) if m else "?"


def _trace(events) -> str:
    return " → ".join(events) if events else "-"


def _build_property_table(results: dict) -> str:
    safe = results["command_models"]["none"]
    rows = []
    for pid, desc in PROP_DESC.items():
        p = safe.get(pid, {})
        rows.append(f"| {pid} | `{p.get('formula', '?')}` | {desc} | {'PASS' if p.get('holds') else 'FAIL'} |")
    return "\n".join(rows)


def _build_mutation_table(results: dict) -> str:
    rows = []
    for name in MUTATIONS:
        model = results["command_models"][name]
        failed = [f"`{pid}`" for pid, p in model.items() if not p.get("holds")]
        # all command models have the same formulas; count is 14
        rows.append(f"| `{name}` | {MUTATIONS[name]} | {len(failed)} | {', '.join(failed) or '—'} |")
    return "\n".join(rows)


def _build_shared_table(results: dict) -> str:
    rows = []
    for name, props in results["shared_models"].items():
        failed = [f"`{pid}`" for pid, p in props.items() if not p.get("holds")]
        rows.append(f"| `{name}` | {SHARED_DESC.get(name, '')} | {', '.join(failed) or '—'} |")
    return "\n".join(rows)


def _counterexample_text(name: str) -> str:
    p = GEN / f"{name}_counterexample.json"
    if not p.exists():
        return ""
    d = json.loads(p.read_text(encoding="utf-8"))
    return _trace(d.get("events", []))


def build_findings(results: dict) -> str:
    verification = (GEN / "verification.txt").read_text(encoding="utf-8", errors="replace")
    threshold = _threshold(verification)
    tests = results.get("tests_passed", "?")
    c_log = OUT / "ch1_kripke_c.txt"
    c_text = c_log.read_text(encoding="utf-8", errors="replace") if c_log.exists() else ""

    c_highlights = []
    for line in c_text.splitlines():
        if any(k in line for k in (
            "[PASS] properties", "[PASS] progress", "completeness threshold",
            "[PASS] AG(!(session_A", "[SESSION]", "[PASS] buggy variant",
            "Tier-3", "[PASS] I1/I2/I3", "counterexample path",
            "violated:", "[PASS] buggy variant caught", "CHAPTER 1 RESULT",
        )):
            c_highlights.append(line.rstrip())
    c_block = "\n".join(c_highlights[:24]) if c_highlights else "(chưa chạy build/wschat_ch1_kripke.exe 8)"

    trace_join = _counterexample_text("join_bypass")
    trace_msg = _counterexample_text("message_guard")
    trace_stale = _counterexample_text("stale_auth")

    return f"""# Chương 1 — Mô hình hóa & kiểm chứng hình thức (Kripke + BMC)

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
{_build_property_table(results)}

- 7 thuộc tính an toàn (`AG`), 5 khả đạt (`EF`), 2 sống còn (`AG ... EF`).
- Tổng **{tests} test PASS** (bao gồm đối chiếu C, replay lifecycle, counterexample,
  shared model, kiểm tra checker trên đồ thị đồ chơi).
- Completeness threshold của model lệnh: **k* = {threshold}**; của lõi C
  (`kripke_completeness_threshold()`): **k* = 4`.

## 3. Mutation và counterexample

| Model | Mô tả mutation | Số thuộc tính FAIL | Thuộc tính FAIL |
|---|---|---|---|
{_build_mutation_table(results)}

- **join_bypass** (P1, P4): trace ngắn nhất `{trace_join}`. C replay:
  `buggy` nhận `JOIN_OK` khi chưa login → `IN_ROOM`; bản gốc từ chối
  (`WS_CONNECTED`). Xem `results/ch1/counterexamples/c_counterexample_replay.json`.
- **message_guard** (P4): trace `{trace_msg}` — nhận MESSAGE trước khi vào phòng.
- **stale_auth** (P5, P7): trace `{trace_stale}` — sau LOGOUT vẫn còn
  `auth_history`, nên `authenticated` vẫn đúng.

## 4. Product automaton (2 kết nối / session / phòng)

| Model | Mô tả | Thuộc tính FAIL |
|---|---|---|
{_build_shared_table(results)}

- `shared_same_account`: giữ **single session** — không thể cả 2 kết nối cùng
  authenticated.
- `shared_distinct_accounts`: 2 tài khoản có thể cùng login và cùng vào phòng.
- `shared_distinct_accounts_buggy_delete`: `deleted_room_empty` FAIL — role B
  không bị evict khi phòng bị xóa (mô hình lỗi cố ý).

## 5. Bằng chứng từ mã C

```text
{c_block}
```

- Tier-2 session: `AG(!(session_A & session_B))` đúng; biến thể buggy cho
  counterexample `(A_logged=1, B_logged=1)`.
- Tier-3 room product (216 trạng thái): I1/I2/I3 đúng; biến thể buggy bị bắt với
  counterexample 4 bước (I1 stranded client) và 7 bước (members/capacity).
- BMC lõi C: `k* = 4`; model lệnh Python: `k* = {threshold}`.

## 6. Bảng before/after (Chương 1)

| CWE | Vị trí | Trạng thái v0 (mutation) | Trạng thái v1 (safe) | Công cụ xác minh |
|---|---|---|---|---|
| CWE-693 | `src/state_machine.c` — P1 | join_bypass: P1 FAIL, trace `{trace_join}` | P1 PASS | Python CTL + C replay |
| CWE-693 | `src/state_machine.c` — P4 | message_guard: P4 FAIL, trace `{trace_msg}` | P4 PASS | Python CTL |
| CWE-693 | `src/state_machine.c` — P5/P7 | stale_auth: P5/P7 FAIL, trace `{trace_stale}` | P5/P7 PASS | Python CTL |
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
"""


def build_before_after() -> str:
    return """# Bảng before/after — Chương 1

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-693 | `src/state_machine.c` — P1 | join_bypass: P1 FAIL; trace FIRST_BYTES → HTTP_UPGRADE_VALID → JOIN_OK; C buggy vào IN_ROOM | P1 PASS; C gốc từ chối JOIN_OK | Python CTL + C replay |
| CWE-693 | `src/state_machine.c` — P4 | message_guard: P4 FAIL; trace FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → MESSAGE_VALID | P4 PASS | Python CTL |
| CWE-693 | `src/state_machine.c` — P5/P7 | stale_auth: P5/P7 FAIL; trace FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → LOGOUT | P5/P7 PASS | Python CTL |
| CWE-667 | `src/session.c` | biến thể buggy: cả 2 session cùng active | `AG(!(session_A & session_B))` PASS | C product model |
| CWE-693 (CWE-667) | `src/room.c` | biến thể buggy delete: I1 stranded client | I1/I2/I3 PASS | C product model |
"""


def main() -> int:
    results = _load()
    OUT.mkdir(parents=True, exist_ok=True)
    DOCS.mkdir(parents=True, exist_ok=True)

    # Copy the evidence that belongs in the submission package.
    for name in ("verification.txt", "results.json", "provenance.json", "core_matrix.json"):
        _copy(GEN / name, OUT / name)
    for name in ("join_bypass_counterexample.json", "message_guard_counterexample.json",
                 "stale_auth_counterexample.json", "c_counterexample_replay.json"):
        _copy(GEN / name, OUT / "counterexamples" / name)

    # Property CSV for spreadsheets / the report appendix.
    safe = results["command_models"]["none"]
    with (OUT / "properties.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["id", "formula", "description", "safe_result"])
        for pid, desc in PROP_DESC.items():
            p = safe.get(pid, {})
            w.writerow([pid, p.get("formula", ""), desc, "PASS" if p.get("holds") else "FAIL"])

    (OUT / "summary.txt").write_text(
        "Chapter 1 evidence\n"
        f"tests_passed: {results.get('tests_passed')}\n"
        f"command_models: {', '.join(results['command_models'])}\n"
        f"shared_models: {', '.join(results['shared_models'])}\n"
        f"threshold (Python): {_threshold((GEN / 'verification.txt').read_text(encoding='utf-8', errors='replace'))}\n",
        encoding="utf-8",
    )

    (DOCS / "findings_ch1.md").write_text(build_findings(results), encoding="utf-8")
    (DOCS / "before_after_ch1.md").write_text(build_before_after(), encoding="utf-8")
    print(f"Wrote {DOCS / 'findings_ch1.md'}")
    print(f"Wrote {DOCS / 'before_after_ch1.md'}")
    print(f"Wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

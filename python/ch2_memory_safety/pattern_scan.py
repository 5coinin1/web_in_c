"""Pattern scanner for the Chapter-2 memory-safety audit target.

The scanner is deliberately small and rule-based (the same idea as
``ch2_memsafe/pattern_scanner.py`` in the course toolkit): it scans
``src/auth.c``, tracks which lines are active in the vulnerable (``-DVULN``)
and fixed views, and reports the three injected bugs plus generic banned
functions.

Usage:
    python3 python/ch2_memory_safety/pattern_scan.py [src/auth.c]
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, List, Tuple


ROOT = Path(__file__).resolve().parents[2]


@dataclass
class PatternFinding:
    file: str
    line: int
    variant: str          # "vuln", "fixed" or "both"
    rule: str
    cwe: str
    severity: str
    message: str
    code: str

    def to_dict(self) -> dict:
        return asdict(self)


# Functions that should never appear in new code (CWE mapping follows the
# course checklist).  strncpy is intentionally absent: it is used safely in
# auth.c for a fixed 32-byte username buffer.
BANNED = {
    "strcpy":  ("CWE-120", "HIGH",   "Unbounded copy into a fixed-size destination"),
    "strcat":  ("CWE-120", "HIGH",   "Unbounded concatenation into a fixed-size destination"),
    "sprintf": ("CWE-134", "MEDIUM", "Unbounded formatted output; use snprintf"),
    "gets":    ("CWE-242", "HIGH",   "Unbounded read from stdin"),
}

_CALL_RE = {name: re.compile(rf"\b{name}\s*\(") for name in BANNED}


def _views(lines: List[str]) -> Tuple[List[bool], List[bool]]:
    """Return (active_in_vuln, active_in_fixed) for every source line.

    Lines outside a ``VULN`` conditional are active in both builds.  Other
    conditionals (``_WIN32`` etc.) keep the surrounding state: the scanner
    targets the parser, whose VULN branches are the only relevant ones.
    """
    vuln: List[bool] = []
    fixed: List[bool] = []
    stack: List[tuple[bool, bool, str, bool]] = []
    v, f = True, True

    for line in lines:
        stripped = line.lstrip()
        if stripped.startswith("#ifdef") and "VULN" in stripped:
            stack.append((v, f, "ifdef", False))
            v, f = True, False
        elif stripped.startswith("#ifndef") and "VULN" in stripped:
            stack.append((v, f, "ifndef", False))
            v, f = False, True
        elif stripped.startswith("#if"):
            stack.append((v, f, "other", False))
        elif stripped.startswith("#else") and stack:
            pv, pf, kind, _ = stack[-1]
            stack[-1] = (pv, pf, kind, True)
            if kind == "ifdef":
                v, f = False, True
            elif kind == "ifndef":
                v, f = True, False
            else:
                v, f = pv, pf
        elif stripped.startswith("#endif") and stack:
            pv, pf, _kind, _else = stack.pop()
            v, f = pv, pf

        vuln.append(v)
        fixed.append(f)

    return vuln, fixed


def _variant(v: bool, f: bool) -> str:
    if v and f:
        return "both"
    return "vuln" if v else "fixed"


def scan_file(path: Path) -> List[PatternFinding]:
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    vuln, fixed = _views(lines)
    findings: List[PatternFinding] = []

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("//") or stripped.startswith("*"):
            continue

        variant = _variant(vuln[idx], fixed[idx])

        # ---- Bug C: header length check is one byte short -----------------
        # This line is inside #ifdef VULN, so it is present only in that build.
        if re.search(r"\blen\s*<\s*11\b", line) and vuln[idx]:
            findings.append(PatternFinding(
                str(path.relative_to(ROOT)), idx + 1, "vuln",
                "header-length-off-by-one", "CWE-193", "HIGH",
                "Header accepts an 11-byte store; get_u32(buf + 8) then reads "
                "buf[8..11], one byte past the end. The fixed bound is len < 12.",
                stripped,
            ))

        # ---- Bug A: file-controlled count is not capped -------------------
        # The count assignment is common to both builds.  The cap lives in the
        # #ifndef VULN branch, so it is invisible in the vulnerable view.
        if re.search(r"\bcount\s*=\s*get_u32\s*\(\s*buf\s*\+\s*8\s*\)", line) and vuln[idx]:
            window_end = min(len(lines), idx + 12)
            capped = any(
                "count > MAX_ACCOUNTS" in lines[j] and vuln[j]
                for j in range(idx, window_end)
            )
            if not capped:
                findings.append(PatternFinding(
                    str(path.relative_to(ROOT)), idx + 1, "vuln",
                    "unbounded-count", "CWE-129", "HIGH",
                    "File-controlled count is used as the loop bound and as an "
                    "index into g_accounts[MAX_ACCOUNTS] (256) without a cap; "
                    "a crafted store writes past the global array (CWE-787).",
                    stripped,
                ))

        # ---- Bug B: record offset is not checked against len --------------
        # The copy is common; the overflow-safe check is in #ifndef VULN.
        if re.search(r"\bmemcpy\s*\(\s*a->username\s*,\s*buf\s*\+\s*off\s*,\s*32\s*\)", line) and vuln[idx]:
            start = max(0, idx - 14)
            guarded = any(
                ("off > len" in lines[j] or "RECORD_SIZE > len - off" in lines[j])
                and vuln[j]
                for j in range(start, idx)
            )
            if not guarded:
                findings.append(PatternFinding(
                    str(path.relative_to(ROOT)), idx + 1, "vuln",
                    "unchecked-record-offset", "CWE-125", "HIGH",
                    "Record copy uses off = 12 + i*88 without checking "
                    "off/off+88 against len; a short store causes an "
                    "out-of-bounds heap read.",
                    stripped,
                ))

        # ---- Generic banned functions ------------------------------------
        for name, (cwe, severity, message) in BANNED.items():
            if _CALL_RE[name].search(line):
                findings.append(PatternFinding(
                    str(path.relative_to(ROOT)), idx + 1, variant,
                    f"banned-function:{name}", cwe, severity, message, stripped,
                ))

    return findings


def render(findings: Iterable[PatternFinding]) -> str:
    findings = list(findings)
    if not findings:
        return "No pattern findings.\n"
    out = [f"{len(findings)} pattern finding(s):"]
    for f in findings:
        out.append(f"  {f.file}:{f.line} [{f.variant}] {f.rule} ({f.cwe}, {f.severity})")
        out.append(f"      {f.message}")
        out.append(f"      {f.code}")
    return "\n".join(out) + "\n"


def main(argv: List[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    target = Path(argv[0]) if argv else ROOT / "src" / "auth.c"
    if not target.is_absolute():
        target = (ROOT / target).resolve()

    findings = scan_file(target)
    text = render(findings)
    print(text)

    out_dir = ROOT / "results" / "ch2"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "pattern_scan.txt").write_text(text, encoding="utf-8")
    (out_dir / "pattern_scan.json").write_text(
        json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"Wrote {out_dir / 'pattern_scan.txt'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

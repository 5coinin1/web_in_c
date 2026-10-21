"""Chapter-2 static analysis: cppcheck + the project pattern scanner.

The module wraps ``cppcheck`` (XML v2 output) and records both the vulnerable
(``-DVULN``) and fixed views of ``src/auth.c``.  cppcheck is good at local
style/ownership mistakes but, as the audit shows, it does *not* find the three
injected bounds bugs; the pattern scanner and ASan are the tools that do.

Usage:
    python3 python/ch2_memory_safety/static_check.py
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List

try:                       # script: python3 static_check.py
    import pattern_scan
except ImportError:        # package: from ch2_memory_safety import static_check
    from . import pattern_scan


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results" / "ch2"
TARGET = ROOT / "src" / "auth.c"
INCLUDES = [ROOT / "src", ROOT / "python" / "ch4_fuzzing" / "stubs"]


@dataclass
class CppcheckFinding:
    file: str
    line: int
    severity: str
    cwe: str | None
    message: str
    check_id: str


@dataclass
class CppcheckReport:
    findings: List[CppcheckFinding] = field(default_factory=list)

    def by_severity(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return dict(sorted(counts.items()))

    def memory_findings(self) -> List[CppcheckFinding]:
        """Findings whose CWE is in the memory-safety family."""
        wanted = {"119", "120", "121", "122", "125", "129", "131", "190",
                  "193", "401", "415", "416", "476", "787"}
        return [f for f in self.findings if f.cwe in wanted]

    def summary(self) -> str:
        counts = self.by_severity()
        if not counts:
            return "No cppcheck findings."
        return (f"{len(self.findings)} finding(s): "
                + ", ".join(f"{k}={v}" for k, v in counts.items()))


class CppcheckNotFoundError(RuntimeError):
    pass


def _parse_xml(xml_text: str) -> CppcheckReport:
    report = CppcheckReport()
    if not xml_text.strip():
        return report
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return report

    errors = root.find("errors")
    if errors is None:
        return report

    for err in errors.findall("error"):
        location = err.find("location")
        line = 0
        file = "?"
        if location is not None:
            file = location.get("file", "?")
            try:
                line = int(location.get("line", "0"))
            except ValueError:
                line = 0
        report.findings.append(CppcheckFinding(
            file=file,
            line=line,
            severity=err.get("severity", "unknown"),
            cwe=err.get("cwe"),
            message=err.get("msg", ""),
            check_id=err.get("id", ""),
        ))
    return report


def run_cppcheck(vuln: bool) -> CppcheckReport:
    exe = shutil.which("cppcheck")
    if not exe:
        raise CppcheckNotFoundError(
            "cppcheck not found in PATH; install it in WSL with "
            "'sudo apt-get install cppcheck'"
        )

    cmd = [
        exe,
        "--enable=all",
        "--inconclusive",
        "--std=c11",
        "--suppress=missingIncludeSystem",
        "--xml",
        "--xml-version=2",
    ]
    for inc in INCLUDES:
        cmd.append(f"-I{inc}")
    if vuln:
        cmd.append("-DVULN")
    cmd.append(str(TARGET))

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    # cppcheck writes its XML report to stderr.
    xml_text = proc.stderr
    OUT.mkdir(parents=True, exist_ok=True)
    tag = "vuln" if vuln else "fixed"
    (OUT / f"cppcheck_{tag}.xml").write_text(xml_text, encoding="utf-8")
    return _parse_xml(xml_text)


def _report_text(tag: str, report: CppcheckReport) -> str:
    lines = [f"cppcheck ({tag}): {report.summary()}"]
    for f in report.findings:
        lines.append(
            f"  [{f.severity}] {f.file}:{f.line} ({f.check_id})"
            f"{' CWE-' + f.cwe if f.cwe else ''} {f.message}"
        )
    return "\n".join(lines) + "\n"


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    payload: dict = {}

    for tag, vuln in (("vuln", True), ("fixed", False)):
        try:
            report = run_cppcheck(vuln)
        except CppcheckNotFoundError as exc:
            print(f"[SKIP] {exc}")
            payload[tag] = {"available": False, "error": str(exc)}
            continue

        text = _report_text(tag, report)
        (OUT / f"cppcheck_{tag}.txt").write_text(text, encoding="utf-8")
        print(text)
        payload[tag] = {
            "available": True,
            "summary": report.summary(),
            "by_severity": report.by_severity(),
            "memory_findings": [asdict(f) for f in report.memory_findings()],
            "findings": [asdict(f) for f in report.findings],
        }

    findings = pattern_scan.scan_file(TARGET)
    pattern_text = pattern_scan.render(findings)
    (OUT / "pattern_scan.txt").write_text(pattern_text, encoding="utf-8")
    (OUT / "pattern_scan.json").write_text(
        json.dumps([f.to_dict() for f in findings], ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(pattern_text)
    payload["pattern_scan"] = {
        "count": len(findings),
        "by_cwe": _count_by_cwe(findings),
        "findings": [f.to_dict() for f in findings],
    }

    (OUT / "static_summary.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(f"Wrote {OUT / 'static_summary.json'}")
    return 0


def _count_by_cwe(findings) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.cwe] = counts.get(f.cwe, 0) + 1
    return dict(sorted(counts.items()))


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Regenerate the per-chapter evidence reports and check prerequisites.

This script does NOT re-run the analyses (Ch1 verify / Ch2 ASan / Ch3 SMT /
Ch4 fuzzing); it rebuilds the Markdown reports from the evidence already in
``results/`` and ``python/*/generated``.

Usage (Windows or WSL):
    python3 tools/build_evidence.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

STEPS = [
    (
        "Ch1",
        ROOT / "python" / "ch1_kripke" / "report.py",
        ROOT / "python" / "ch1_kripke" / "generated" / "results.json",
        "python/ch1_kripke/verify.py --bridge <ch1_chat_bridge.exe>",
    ),
    (
        "Ch2",
        ROOT / "python" / "ch2_memory_safety" / "report.py",
        ROOT / "results" / "ch2" / "results.json",
        "python/ch2_memory_safety/run_ch2.py",
    ),
    (
        "Ch3",
        ROOT / "python" / "ch3_smt" / "report.py",
        ROOT / "results" / "ch3" / "results.json",
        "python/ch3_smt/run.py --output results/ch3",
    ),
    (
        "Ch4",
        ROOT / "python" / "ch4_fuzzing" / "report.py",
        ROOT / "results" / "ch4" / "run_fuzzing_demo.txt",
        "python/run_fuzzing_demo.py (from python/ dir)",
    ),
]


def main() -> int:
    missing = []
    for name, _script, prerequisite, how in STEPS:
        if not prerequisite.exists():
            missing.append(f"{name}: {prerequisite.relative_to(ROOT)} (chạy: {how})")

    if missing:
        print("Thiếu bằng chứng, chưa thể sinh báo cáo:")
        for m in missing:
            print("  -", m)
        return 1

    failed = 0
    for name, script, _prerequisite, _how in STEPS:
        print(f"== {name}: {script.relative_to(ROOT)}")
        r = subprocess.run([sys.executable, str(script)], cwd=ROOT)
        if r.returncode != 0:
            failed += 1
            print(f"  [FAIL] rc={r.returncode}")
        else:
            print("  [OK]")

    print()
    if failed:
        print(f"{failed} report(s) failed")
        return 1
    print("All chapter reports regenerated. See docs/ and results/.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

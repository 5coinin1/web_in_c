"""Tests for the Chapter-2 memory-safety package.

Runnable with pytest or standalone (no pytest required):

    python3 python/tests/test_ch2_memory_safety.py
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(ROOT / "python" / "ch2_memory_safety"))

import asan_runner  # noqa: E402
import pattern_scan  # noqa: E402
import report  # noqa: E402


def test_pattern_scanner_finds_three_injected_bugs():
    findings = pattern_scan.scan_file(ROOT / "src" / "auth.c")
    by_cwe = {f.cwe: f for f in findings}
    assert set(by_cwe) == {"CWE-193", "CWE-129", "CWE-125"}, by_cwe
    assert by_cwe["CWE-193"].line == 114
    assert by_cwe["CWE-129"].line == 122
    assert by_cwe["CWE-125"].line == 142


def test_asan_frame_is_normalised_to_repo_relative_path():
    sample = (
        "    #1 0x55 in auth_store_parse "
        "/mnt/c/Users/lenovo/Desktop/temp/web_in_c/src/auth.c:142\n"
    )
    assert asan_runner._first_src_frame(sample) == "src/auth.c:142"


def test_vuln_expectation_matches_asan_witness():
    res = asan_runner.RunResult(
        variant="vuln", poc="poc_count.dat", returncode=1,
        stdout="", stderr="", log="",
        error="global-buffer-overflow", access="WRITE", size=32,
        frame="src/auth.c:142",
    )
    assert asan_runner._check_vuln(res) is True

    res.frame = "src/auth.c:999"
    assert asan_runner._check_vuln(res) is False


def test_fixed_build_must_be_clean():
    ok = asan_runner.RunResult(
        variant="fixed", poc="poc_count.dat", returncode=0,
        stdout="auth_store_parse -> rc=0 accounts=256\n", stderr="", log="",
        accounts=256, parser_rc=0,
    )
    assert asan_runner._check_fixed(ok) is True

    bad = asan_runner.RunResult(
        variant="fixed", poc="poc_count.dat", returncode=1,
        stdout="", stderr="ERROR: AddressSanitizer", log="",
        error="global-buffer-overflow",
    )
    assert asan_runner._check_fixed(bad) is False


def test_before_after_table_covers_all_cwes():
    table = report.build_before_after()
    for cwe in ("CWE-193", "CWE-787", "CWE-125"):
        assert cwe in table


def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"[PASS] {fn.__name__}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"[FAIL] {fn.__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())

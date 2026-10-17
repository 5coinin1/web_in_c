"""Pytest-style tests for the Chapter-4 fuzzing toolkit.

Runnable with pytest *or* standalone (no pytest needed):

    python3 tests/test_ch4_fuzzing.py

Run under Linux/WSL to get the AddressSanitizer-backed crash assertions.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ch4_fuzzing import (  # noqa: E402
    build_target, asan_available,
    black_box_fuzz, coverage_guided_fuzz, measure_coverage, reset_gcda, run_target, is_crash,
    seed_corpus, structural_gate, structural_crash, z3_solve_gate,
)

_T = None


def target():
    global _T
    if _T is None:
        _T = build_target(vuln=True, coverage=True)
    return _T


def test_structural_gate_is_accepted():
    t = target()
    rc, out, _ = run_target(t.binary, structural_gate(), t.work_dir)
    assert rc == 0 and "rc=0" in out, f"gate not accepted: rc={rc} out={out!r}"


def test_z3_solves_the_magic():
    gate, _ = z3_solve_gate()
    assert gate[:4] == b"WSAC", f"z3 gate = {gate!r}"


def test_structural_crash_triggers_asan():
    if not asan_available():
        print("skip: ASan not available (run under WSL/Linux)")
        return
    t = target()
    rc, _, err = run_target(t.binary, structural_crash(), t.work_dir)
    assert "AddressSanitizer" in err, f"expected ASan report, got rc={rc}"


def test_black_box_fails_to_guess_magic():
    t = target()
    r = black_box_fuzz(t, max_iterations=2000, max_len=32, seed=1)
    # 4-byte magic -> P ~ 2^-32; random should not find it in 2000 tries.
    assert not r.found, "black-box unexpectedly passed the magic gate"


def test_coverage_guided_reaches_at_least_seed_coverage():
    t = target()
    reset_gcda(t.work_dir)
    for s in seed_corpus():
        run_target(t.binary, s, t.work_dir)
    seed_cov = measure_coverage(t.source, t.work_dir)
    r = coverage_guided_fuzz(t, max_iterations=300, seed=1,
                             seeds=seed_corpus(), measure_every=20)
    reached = max(r.coverage_history, default=seed_cov)
    assert reached >= seed_cov - 0.01, (reached, seed_cov)


def _run_all() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"[PASS] {fn.__name__}")
        except Exception as e:
            failed += 1
            print(f"[FAIL] {fn.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())

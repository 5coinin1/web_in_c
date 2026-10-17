#!/usr/bin/env python3
"""Chapter 4 demo: black-box vs white-box fuzzing on the account-store parser.

Run under Linux/WSL (for AddressSanitizer + gcov):

    wsl -d Ubuntu -e bash -lc "cd /mnt/c/.../web_in_c/python && python3 run_fuzzing_demo.py"

Story told by the numbers:
  * a 4-byte magic makes pure black-box fuzzing hopeless (~2^-48);
  * coverage-guided fuzzing gets no per-byte gradient from a single memcmp,
    so WITHOUT seeds it is no better than black-box;
  * WITH seeds (structural knowledge) it starts deep and explores further;
  * white-box construction / Z3 solves the gate in one step and reaches the
    injected bug that ASan then reports.
"""
from __future__ import annotations

import time

from ch4_fuzzing import (
    build_target, asan_available, black_box_fuzz, coverage_guided_fuzz,
    measure_coverage, reset_gcda, run_target, is_crash,
    seed_corpus, write_seed_dir, structural_gate, structural_crash, z3_solve_gate,
)

BLACKBOX_ITERS = 1500
NOSEED_ITERS = 300
SEEDED_ITERS = 400


def timed(fn, *a, **k):
    t0 = time.perf_counter()
    r = fn(*a, **k)
    return r, time.perf_counter() - t0


def main() -> int:
    print("=" * 70)
    print(" CHAPTER 4 - FUZZING: black-box vs white-box (account-store parser)")
    print("=" * 70)

    asan = asan_available()
    print(f"ASan available : {asan}"
          + ("" if asan else "   (build without it -> weak crash oracle; run under WSL)"))
    t = build_target(vuln=True, coverage=True)
    print(f"target         : {t.binary}")
    print(f"seed corpus    : {write_seed_dir(t.work_dir / 'seeds')} seeds -> {t.work_dir / 'seeds'}")

    # Coverage after simply running the seeds through the parser.
    reset_gcda(t.work_dir)
    for s in seed_corpus():
        run_target(t.binary, s, t.work_dir)
    seed_cov = measure_coverage(t.source, t.work_dir)
    print(f"coverage after seeding: {seed_cov:.2f}%")

    # ---- 1. black-box ----
    print("\n[1] BLACK-BOX (pure random, no feedback) -> pass the magic gate")
    rb, dt = timed(black_box_fuzz, t, max_iterations=BLACKBOX_ITERS, max_len=32, seed=1)
    print(f"    found={rb.kind:<8} tries={rb.iterations:<6} time={dt:.1f}s   "
          f"(P(WSAC) ~ 2^-32, +version 2^-16)")

    # ---- 2. coverage-guided WITHOUT seeds ----
    print("\n[2] COVERAGE-GUIDED, NO seeds -> pass the magic gate")
    rg0, dt0 = timed(coverage_guided_fuzz, t, max_iterations=NOSEED_ITERS,
                     seed=1, seeds=(), measure_every=20)
    print(f"    found={rg0.kind:<8} tries={rg0.iterations:<6} time={dt0:.1f}s   "
          f"(a single memcmp gives no per-byte gradient)")

    # ---- 3. coverage-guided WITH seeds ----
    print("\n[3] COVERAGE-GUIDED, seeded -> aim at the injected bug")
    rg1, dt1 = timed(coverage_guided_fuzz, t, max_iterations=SEEDED_ITERS,
                     seed=1, seeds=seed_corpus(), measure_every=10, want="crash")
    reached = max(rg1.coverage_history, default=seed_cov)
    print(f"    found={rg1.kind:<8} tries={rg1.iterations:<6} time={dt1:.1f}s   "
          f"coverage {reached:.2f}% (seed-only {seed_cov:.2f}%)")

    # ---- 4. white-box: Z3 / structural ----
    print("\n[4] WHITE-BOX: solve the gate, then trigger the bug")
    gate, zsec = z3_solve_gate()
    print(f"    Z3 solved header = {gate!r} in {zsec * 1000:.2f} ms")
    rc, out, _ = run_target(t.binary, structural_gate(), t.work_dir)
    print(f"    structural gate -> rc={rc} accepted={('rc=0' in out)} (1 try)")
    rc, _, err = run_target(t.binary, structural_crash(), t.work_dir)
    asan_line = next((l for l in err.splitlines() if "AddressSanitizer" in l), "")
    kind = "ASan" if asan_line else ("crash" if is_crash(rc, err) else "none")
    print(f"    11-byte off-by-one -> oracle={kind}")
    if asan_line:
        print(f"      {asan_line.strip()[:96]}")

    # ---- summary ----
    print("\n" + "=" * 70)
    print(" SUMMARY")
    print(f"  black-box, no seed      : {rb.iterations} tries -> {rb.kind}")
    print(f"  guided, no seed         : {rg0.iterations} tries -> {rg0.kind}")
    print(f"  guided, seeded          : {rg1.iterations} tries -> {rg1.kind}, cov {reached:.2f}%")
    print(f"  white-box (Z3/struct)   : gate in {zsec * 1000:.1f} ms; bug via {kind}")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

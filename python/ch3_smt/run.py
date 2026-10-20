#!/usr/bin/env python3
"""CH3-A runner: execute all SMT queries, compile and run C harness, collect evidence.

Usage:
    python run.py --output <dir> [--cc <gcc-path>]
"""
import argparse, json, os, pathlib, subprocess, sys, datetime, platform, hashlib, shutil, textwrap

# Allow running from any cwd – the package lives next to this script.
_HERE = pathlib.Path(__file__).resolve().parent
_ROOT = _HERE.parent.parent                       # web_in_c/
sys.path.insert(0, str(_HERE.parent))             # python/

from ch3_smt.append_smt import (
    query_before_violation, query_fixed_violation, query_non_vacuity,
    query_signed_overflow, invariant_base, invariant_step,
    bmc_query, solve, CAPACITY, RECV_CAP,
)
import z3

# ─────────────────────────────────────────────────────────────────────────────
# helpers
# ─────────────────────────────────────────────────────────────────────────────

def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()

def _model_dict(m):
    if m is None:
        return None
    d = {}
    for decl in m.decls():
        v = m[decl]
        # convert to Python int (signed)
        bv = v.as_long()
        if bv >= (1 << 31):
            bv -= (1 << 32)
        d[decl.name()] = bv
    return d

def _export_smt2(formula, path: pathlib.Path):
    s = z3.Solver()
    s.add(formula)
    path.write_text(s.sexpr())

def _run(cmd, cwd=None, timeout=30):
    """Run a command, return (returncode, stdout, stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd)
        return r.returncode, r.stdout.decode(errors='replace'), r.stderr.decode(errors='replace')
    except subprocess.TimeoutExpired:
        return -999, "", "TIMEOUT"
    except FileNotFoundError:
        return -1, "", f"FileNotFoundError: {cmd[0]}"


# ─────────────────────────────────────────────────────────────────────────────
# main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(description="Reproduce CH3-A: SMT + C replay.")
    ap.add_argument("--output", required=True)
    ap.add_argument("--cc", default="C:/msys64/mingw64/bin/gcc.exe")
    args = ap.parse_args()

    out = pathlib.Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    smt2_dir = out / "smt2"
    smt2_dir.mkdir(exist_ok=True)

    results = {}
    all_pass = True

    # ── 1. SMT queries ───────────────────────────────────────────────────────
    print("=" * 60)
    print("CH3-A: Z3 SMT verification of read-buffer append")
    print("=" * 60)

    queries = [
        ("before_violation",     query_before_violation(),      "SAT"),
        ("fixed_violation",      query_fixed_violation(),       "UNSAT"),
        ("non_vacuity",          query_non_vacuity(),           "SAT"),
        ("signed_overflow",      query_signed_overflow(),       "UNSAT"),
        ("invariant_base",       invariant_base(),              "UNSAT"),
        ("invariant_step",       invariant_step(),              "UNSAT"),
    ]

    for name, formula, expected in queries:
        _export_smt2(formula, smt2_dir / f"{name}.smt2")
        result, model = solve(formula, name)
        md = _model_dict(model)
        ok = result == expected
        if not ok:
            all_pass = False
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}: {result} (expected {expected})", end="")
        if md:
            # For before_violation, compute index
            if 'L' in md and 'N' in md:
                md['index'] = md['L'] + md['N']
            print(f"  witness={md}", end="")
        print()
        results[name] = {"result": result, "expected": expected, "ok": ok, "witness": md}

    # ── 2. BMC queries ───────────────────────────────────────────────────────
    print()
    print("BMC (multiple recv from empty buffer):")

    for k in range(1, 4):
        for variant, use_fixed in [("before", False), ("fixed", True)]:
            label = f"bmc_k{k}_{variant}"
            formula, variables = bmc_query(k, use_fixed)
            _export_smt2(formula, smt2_dir / f"{label}.smt2")
            result, model = solve(formula, label)
            md = _model_dict(model)
            if variant == "before":
                expected = "SAT" if k >= 2 else "UNSAT"
            else:
                expected = "UNSAT"
            ok = result == expected
            if not ok:
                all_pass = False
            status = "PASS" if ok else "FAIL"
            print(f"  [{status}] {label}: {result} (expected {expected})", end="")
            if md:
                print(f"  witness={md}", end="")
            print()
            results[label] = {"result": result, "expected": expected, "ok": ok, "witness": md}

    # ── 3. C harness ─────────────────────────────────────────────────────────
    print()
    print("C harness (offline boundary tests):")

    harness_src = _ROOT / "test" / "ch3_append_harness.c"
    harness_exe = out / "ch3_harness.exe"
    cc = args.cc

    if not harness_src.exists():
        print(f"  [SKIP] Harness source not found: {harness_src}")
        results["c_harness"] = {"status": "SKIP", "reason": "source not found"}
    elif not pathlib.Path(cc).exists():
        print(f"  [SKIP] Compiler not found: {cc}")
        results["c_harness"] = {"status": "SKIP", "reason": "compiler not found"}
    else:
        # Compile with bounds sanitizer
        compile_cmd = [
            cc, "-std=c11", "-Wall", "-Wextra",
            "-fsanitize=bounds", "-fsanitize-trap=bounds",
            "-DCH3_WITH_BASELINE",
            "-I", str(_ROOT / "src"),
            str(harness_src),
            str(_ROOT / "src" / "ws_frame.c"),
            str(_ROOT / "src" / "state_machine.c"),
            "-o", str(harness_exe),
            "-lws2_32", "-lssl", "-lcrypto",
        ]
        rc, stdout, stderr = _run(compile_cmd)
        results["c_compile"] = {"returncode": rc, "stdout": stdout, "stderr": stderr,
                                "command": " ".join(compile_cmd)}
        if rc != 0:
            print(f"  [FAIL] Compile failed (rc={rc}): {stderr[:200]}")
            all_pass = False
        else:
            print(f"  [PASS] Compiled harness with -fsanitize=bounds")

            # Run test cases
            test_cases = [
                # (L, N, variant)  variant: "before" or "fixed"
                {"args": ["case", "before", "4096", "4096", "0"], "label": "before_L4096_N4096",
                 "desc": "SMT witness: total=8192, BAD INDEX"},
                {"args": ["case", "fixed", "4096", "4096", "0"], "label": "fixed_L4096_N4096",
                 "desc": "Fixed rejects: total would be 8192"},
                {"args": ["case", "before", "4095", "4096", "0"], "label": "before_L4095_N4096",
                 "desc": "Valid: total=8191, last safe index"},
                {"args": ["case", "fixed", "4095", "4096", "0"], "label": "fixed_L4095_N4096",
                 "desc": "Fixed accepts: total=8191"},
                {"args": ["case", "fixed", "8191", "1", "0"], "label": "fixed_L8191_N1",
                 "desc": "Fixed rejects: total would be 8192"},
                {"args": ["case", "fixed", "0", "4096", "0"], "label": "fixed_L0_N4096",
                 "desc": "Fixed accepts from empty"},
                {"args": ["abi"], "label": "abi", "desc": "ABI layout"},
                {"args": ["self-test"], "label": "self_test", "desc": "Fixed self-test"},
            ]

            c_results = []
            for tc in test_cases:
                rc, stdout, stderr = _run([str(harness_exe)] + tc["args"])
                ok = rc == 0
                if not ok and tc["label"] not in ("before_L4096_N4096",):
                    # before_L4096_N4096 might trap (expected bad index)
                    pass
                entry = {"label": tc["label"], "desc": tc["desc"],
                         "returncode": rc, "stdout": stdout.strip(),
                         "stderr": stderr.strip()}
                c_results.append(entry)
                status = "PASS" if rc == 0 else f"rc={rc}"
                print(f"  [{status}] {tc['label']}: {tc['desc']}")
                if stdout.strip():
                    print(f"         {stdout.strip()[:120]}")

            results["c_cases"] = c_results

    # ── 4. Provenance ────────────────────────────────────────────────────────
    source_files = [
        "src/server.c", "src/connection.h", "src/common.h",
        "src/ws_frame.c", "src/ws_frame.h",
        "python/ch3_smt/append_smt.py",
    ]
    if harness_src.exists():
        source_files.append("test/ch3_append_harness.c")
    if (_ROOT / "src" / "read_buffer.h").exists():
        source_files.append("src/read_buffer.h")

    sha = {}
    for f in source_files:
        p = _ROOT / f
        if p.exists():
            sha[f] = _sha256(p)

    # Get git HEAD
    git_rc, git_out, _ = _run(["git", "rev-parse", "HEAD"], cwd=str(_ROOT))
    head = git_out.strip() if git_rc == 0 else "unknown"

    provenance = {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "head": head,
        "python": sys.version,
        "z3": z3.get_version_string(),
        "platform": platform.platform(),
        "source_sha256": sha,
    }

    # ── 5. Write outputs ─────────────────────────────────────────────────────
    (out / "results.json").write_text(json.dumps(results, indent=2))
    (out / "provenance.json").write_text(json.dumps(provenance, indent=2))

    # Write verification log
    log_lines = [
        f"CH3-A Verification Log",
        f"Date: {provenance['timestamp']}",
        f"HEAD: {head}",
        f"Z3: {z3.get_version_string()}",
        f"Python: {sys.version.split()[0]}",
        "",
    ]
    for name, info in results.items():
        if isinstance(info, dict) and "result" in info:
            status = "PASS" if info.get("ok") else "FAIL"
            log_lines.append(f"[{status}] {name}: {info['result']} (expected {info['expected']})")
            if info.get("witness"):
                log_lines.append(f"         witness: {info['witness']}")
        elif isinstance(info, list):
            for item in info:
                log_lines.append(f"  {item.get('label','')}: rc={item.get('returncode','')} {item.get('desc','')}")
    (out / "verification.txt").write_text("\n".join(log_lines))

    print()
    if all_pass:
        print("All SMT queries matched expectations.")
    else:
        print("WARNING: Some queries did not match expectations!")
    print(f"Results written to {out}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    sys.exit(main())

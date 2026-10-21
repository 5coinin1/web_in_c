"""Chapter-2 dynamic evidence: build the parser with ASan/UBSan and run PoCs.

The vulnerable build is the same ``src/auth.c`` compiled with ``-DVULN``; the
fixed build is the default (all bounds checks enabled).  Both are linked with
the tiny OpenSSL stubs from ``python/ch4_fuzzing/stubs`` so no libssl-dev is
needed, and both use the real harness ``test/fuzz_store.c``.

Run inside WSL/Linux:
    python3 python/ch2_memory_safety/asan_runner.py

On Windows use ``run_ch2.py`` (it re-executes this module inside WSL).
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List


ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results" / "ch2"
BUILD = OUT / "build"
POCS = OUT / "pocs"
LOGS = OUT / "asan"

HARNESS = ROOT / "test" / "fuzz_store.c"
AUTH = ROOT / "src" / "auth.c"
LOG = ROOT / "src" / "log.c"
STUBS = ROOT / "python" / "ch4_fuzzing" / "stubs"
STUB_SRC = STUBS / "stub_openssl.c"

CFLAGS = [
    "-std=gnu11", "-g", "-O1",
    "-fsanitize=address,undefined",
    "-fno-omit-frame-pointer",
]
INCLUDES = ["-I", str(ROOT / "src"), "-I", str(STUBS)]

# name -> (ASan error, access, size, top source frame, CWE)
EXPECTED = {
    "poc_count.dat":    ("global-buffer-overflow", "WRITE", 32, "src/auth.c:142", "CWE-787"),
    "poc_short.dat":    ("heap-buffer-overflow",   "READ",  32, "src/auth.c:142", "CWE-125"),
    "poc_offbyone.dat": ("heap-buffer-overflow",   "READ",   1, "src/bytes.h:30",  "CWE-193"),
}

ASAN_RE = re.compile(r"ERROR: AddressSanitizer: ([\w-]+)")
ACCESS_RE = re.compile(r"(READ|WRITE) of size (\d+)")
FRAME_RE = re.compile(r"#\d+ 0x[0-9a-fA-F]+ in (\S+) (\S+:\d+)")


@dataclass
class RunResult:
    variant: str
    poc: str
    returncode: int
    stdout: str
    stderr: str
    log: str
    error: str | None = None
    access: str | None = None
    size: int | None = None
    frame: str | None = None
    accounts: int | None = None
    parser_rc: int | None = None


def _run(cmd: List[str], timeout: int = 120, env: Dict[str, str] | None = None):
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, env=env
    )


def _gcc_version() -> str:
    try:
        r = _run(["gcc", "--version"])
        return r.stdout.splitlines()[0] if r.returncode == 0 else "unknown"
    except Exception:
        return "unknown"


def _toolchain() -> Dict[str, object]:
    return {
        "platform": platform.platform(),
        "gcc": _gcc_version(),
        "python": platform.python_version(),
        "asan": True,
    }


def build(vuln: bool) -> Path:
    if not shutil.which("gcc"):
        raise RuntimeError("gcc not found in PATH (run inside WSL/Linux)")
    BUILD.mkdir(parents=True, exist_ok=True)

    name = "fuzz_store_vuln" if vuln else "fuzz_store_fixed"
    out = BUILD / name
    cmd = ["gcc", *CFLAGS, *INCLUDES]
    if vuln:
        cmd.append("-DVULN")
    cmd += [
        str(HARNESS), str(AUTH), str(LOG), str(STUB_SRC),
        "-o", str(out), "-pthread",
    ]
    r = _run(cmd)
    if r.returncode != 0:
        raise RuntimeError(
            f"build {name} failed:\n{' '.join(cmd)}\n{r.stderr}"
        )
    return out


def _make_pocs() -> None:
    POCS.mkdir(parents=True, exist_ok=True)
    r = _run([sys.executable, str(ROOT / "tools" / "make_pocs.py"), str(POCS)])
    if r.returncode != 0:
        raise RuntimeError(f"make_pocs failed:\n{r.stdout}\n{r.stderr}")


def _first_src_frame(stderr: str) -> str | None:
    for _func, frame in FRAME_RE.findall(stderr):
        # ASan prints absolute paths when the binary was built from /mnt/c/...
        normalized = frame.replace("\\", "/")
        for prefix in ("/src/", "/test/"):
            pos = normalized.find(prefix)
            if pos >= 0:
                normalized = normalized[pos + 1:]
                break
        if normalized.startswith(("src/", "test/")):
            return normalized
    return None


def run_case(binary: Path, poc: Path, variant: str) -> RunResult:
    LOGS.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=0:abort_on_error=0:symbolize=1"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:halt_on_error=0"

    t0 = time.perf_counter()
    r = _run([str(binary), str(poc)], timeout=60, env=env)
    elapsed = time.perf_counter() - t0

    error = ASAN_RE.search(r.stderr)
    access = ACCESS_RE.search(r.stderr)
    frame = _first_src_frame(r.stderr)
    acc = re.search(r"accounts=(-?\d+)", r.stdout)
    parser_rc = re.search(r"\brc=(-?\d+)", r.stdout)

    log_name = f"{variant}_{poc.name}.txt"
    log_path = LOGS / log_name
    log_path.write_text(
        " ".join([str(binary), str(poc)]) + "\n"
        f"returncode: {r.returncode}\n"
        f"elapsed_s: {elapsed:.3f}\n"
        "--- stdout ---\n" + r.stdout +
        "--- stderr ---\n" + r.stderr,
        encoding="utf-8",
    )

    return RunResult(
        variant=variant,
        poc=poc.name,
        returncode=r.returncode,
        stdout=r.stdout,
        stderr=r.stderr,
        log=str(log_path.relative_to(ROOT)),
        error=error.group(1) if error else None,
        access=access.group(1) if access else None,
        size=int(access.group(2)) if access else None,
        frame=frame,
        accounts=int(acc.group(1)) if acc else None,
        parser_rc=int(parser_rc.group(1)) if parser_rc else None,
    )


def _check_vuln(res: RunResult) -> bool:
    exp = EXPECTED[res.poc]
    return (
        res.error == exp[0]
        and res.access == exp[1]
        and res.size == exp[2]
        and res.frame == exp[3]
    )


def _check_fixed(res: RunResult) -> bool:
    return res.returncode == 0 and res.error is None


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    _make_pocs()

    print("=" * 70)
    print(" CHAPTER 2 - MEMORY SAFETY: ASan/UBSan evidence")
    print("=" * 70)
    print(f"toolchain: {_toolchain()['gcc']}")
    print(f"PoCs     : {POCS}")
    print()

    vuln_bin = build(vuln=True)
    fixed_bin = build(vuln=False)
    print(f"built    : {vuln_bin.relative_to(ROOT)}")
    print(f"built    : {fixed_bin.relative_to(ROOT)}")
    print()

    pocs = sorted(POCS.glob("poc_*.dat"))
    if not pocs:
        print("no PoCs generated", file=sys.stderr)
        return 1

    runs: List[RunResult] = []

    print("-- vulnerable build (-DVULN) --")
    for poc in pocs:
        res = run_case(vuln_bin, poc, "vuln")
        runs.append(res)
        ok = _check_vuln(res)
        print(
            f"  [{'PASS' if ok else 'FAIL'}] {poc.name}: "
            f"{res.error or 'no ASan'} {res.access or ''} "
            f"size={res.size} frame={res.frame} (expected {EXPECTED[poc.name][4]})"
        )

    print("\n-- fixed build (default) --")
    for poc in pocs:
        res = run_case(fixed_bin, poc, "fixed")
        runs.append(res)
        ok = _check_fixed(res)
        print(
            f"  [{'PASS' if ok else 'FAIL'}] {poc.name}: "
            f"rc={res.returncode} parser_rc={res.parser_rc} "
            f"accounts={res.accounts} asan={res.error or 'none'}"
        )

    vuln_ok = all(_check_vuln(r) for r in runs if r.variant == "vuln")
    fixed_ok = all(_check_fixed(r) for r in runs if r.variant == "fixed")
    all_ok = vuln_ok and fixed_ok

    payload = {
        "toolchain": _toolchain(),
        "target": "src/auth.c::auth_store_parse",
        "harness": "test/fuzz_store.c",
        "builds": {
            "vuln": str(vuln_bin.relative_to(ROOT)),
            "fixed": str(fixed_bin.relative_to(ROOT)),
            "flags": " ".join(CFLAGS),
        },
        "expected": {
            k: {
                "error": v[0], "access": v[1], "size": v[2],
                "frame": v[3], "cwe": v[4],
            }
            for k, v in EXPECTED.items()
        },
        "runs": [
            {
                "variant": r.variant, "poc": r.poc,
                "returncode": r.returncode,
                "error": r.error, "access": r.access, "size": r.size,
                "frame": r.frame, "accounts": r.accounts,
                "parser_rc": r.parser_rc, "log": r.log,
            }
            for r in runs
        ],
        "checks": {
            "vuln_bugs_found": sum(1 for r in runs if r.variant == "vuln" and _check_vuln(r)),
            "fixed_clean": sum(1 for r in runs if r.variant == "fixed" and _check_fixed(r)),
            "vuln_ok": vuln_ok,
            "fixed_ok": fixed_ok,
            "all_expected": all_ok,
        },
    }
    (OUT / "results.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    summary = [
        "Chapter 2 - ASan/UBSan evidence",
        f"generated: {time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"toolchain: {payload['toolchain']['gcc']}",
        "",
        "variant  poc                     asan/error                 access size frame              parser_rc accounts",
        "-------  ----------------------  -------------------------  ------ ---- ----------------  --------- --------",
    ]
    for r in runs:
        summary.append(
            f"{r.variant:<7}  {r.poc:<22}  {str(r.error or 'none'):<25}  "
            f"{str(r.access or '-'):<6} {str(r.size or '-'):<4} {str(r.frame or '-'):<16}  "
            f"{str(r.parser_rc if r.parser_rc is not None else '-'):<9} {str(r.accounts if r.accounts is not None else '-')}"
        )
    summary += [
        "",
        f"vulnerable bugs found : {payload['checks']['vuln_bugs_found']}/3",
        f"fixed cases clean     : {payload['checks']['fixed_clean']}/3",
        f"all expectations met  : {all_ok}",
    ]
    text = "\n".join(summary) + "\n"
    (OUT / "summary.txt").write_text(text, encoding="utf-8")
    print("\n" + text)
    return 0 if all_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

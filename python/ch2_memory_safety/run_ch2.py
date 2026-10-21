#!/usr/bin/env python3
"""Run the complete Chapter-2 pipeline: static check -> ASan/UBSan -> report.

On Windows the script re-executes itself inside WSL (Ubuntu by default), because
AddressSanitizer/UBSan are available there and not in the MinGW toolchain:

    py -3 python/ch2_memory_safety/run_ch2.py

Inside WSL/Linux it runs directly:

    python3 python/ch2_memory_safety/run_ch2.py
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
DISTRO = os.environ.get("WSL_DISTRO", "Ubuntu")


def _windows_to_wsl(path: Path) -> str:
    r = subprocess.run(
        ["wsl", "-d", DISTRO, "-e", "wslpath", "-a", str(path)],
        capture_output=True, text=True,
    )
    if r.returncode != 0 or not r.stdout.strip():
        raise RuntimeError(
            f"cannot translate path to WSL: {r.stderr.strip() or r.stdout.strip()}"
        )
    return r.stdout.strip()


def _dispatch_to_wsl() -> int:
    try:
        wsl_root = _windows_to_wsl(ROOT)
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        print("Run this script inside WSL instead.", file=sys.stderr)
        return 2

    extra = " ".join(shlex.quote(a) for a in sys.argv[1:])
    inner = (
        f"cd {shlex.quote(wsl_root)} && "
        f"python3 python/ch2_memory_safety/run_ch2.py {extra}"
    )
    print(f"[WSL] {DISTRO}: {inner}")
    return subprocess.call(["wsl", "-d", DISTRO, "-e", "bash", "-lc", inner])


def main() -> int:
    if os.name == "nt":
        return _dispatch_to_wsl()

    here = Path(__file__).resolve().parent
    sys.path.insert(0, str(here))

    import asan_runner
    import report
    import static_check

    print("\n### 1/3 static analysis ########################################")
    rc_static = static_check.main()

    print("\n### 2/3 ASan/UBSan evidence ####################################")
    rc_asan = asan_runner.main()

    print("\n### 3/3 report ################################################")
    rc_report = report.main()

    rc = 0 if (rc_static == 0 and rc_asan == 0 and rc_report == 0) else 1
    print(f"\nChapter 2 finished with rc={rc}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

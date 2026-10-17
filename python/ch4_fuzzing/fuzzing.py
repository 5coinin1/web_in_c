"""Chapter 4 -- dynamic analysis: coverage, black-box and white-box fuzzing.

Three oracles are used, in increasing strength:
  * a parser "gate"  : the input is accepted (rc=0), i.e. it passed the magic
                       + version check -> reached the record-parsing loop.
  * a crash          : the process died on a signal / NTSTATUS crash code, or
                       ASan reported an out-of-bounds access.
  * line coverage    : gcov % over auth.c, the signal a coverage-guided
                       ("white-box") fuzzer maximises.

Black-box = random bytes, no feedback.
Coverage-guided ("white-box" in the AFL sense) = keep mutants that raise the
cumulative gcov coverage and mutate from that corpus.
"""
from __future__ import annotations

import glob
import os
import random
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence


# Windows reports crashes as NTSTATUS codes (exit codes), not negative signals.
_NTSTATUS_CRASH = {
    0xC0000005,  # ACCESS_VIOLATION
    0xC0000006,  # IN_PAGE_ERROR
    0xC000001D,  # ILLEGAL_INSTRUCTION
    0xC0000094,  # INTEGER_DIVIDE_BY_ZERO
    0xC00000FD,  # STACK_OVERFLOW
    0xC0000374,  # HEAP_CORRUPTION
    0xC0000409,  # STACK_BUFFER_OVERRUN
}


def is_crash(rc: int, stderr: str = "") -> bool:
    if rc is None:
        return False
    if rc < 0:                                   # killed by a POSIX signal
        return True
    if (rc & 0xFFFFFFFF) in _NTSTATUS_CRASH:     # Windows crash code
        return True
    return "AddressSanitizer" in stderr          # ASan reported an error


def _accepted(stdout: str) -> bool:
    m = re.search(r"rc=(-?\d+)", stdout)
    return bool(m) and int(m.group(1)) == 0


def run_target(binary: Path, data: bytes, work_dir: Path, timeout: float = 5.0):
    """Run the target on `data`. Returns (returncode, stdout, stderr)."""
    inp = Path(work_dir) / "_input.bin"
    inp.write_bytes(data)
    try:
        p = subprocess.run([str(binary), str(inp)],
                           capture_output=True, timeout=timeout)
        return p.returncode, p.stdout.decode("latin-1"), p.stderr.decode("latin-1")
    except subprocess.TimeoutExpired:
        return -999, "", "timeout"


def reset_gcda(work_dir: Path) -> None:
    for f in glob.glob(str(Path(work_dir) / "*.gcda")):
        os.remove(f)


def measure_coverage(source_basename: str, work_dir: Path) -> float:
    """Cumulative line-coverage % of `source_basename` from the .gcda counters."""
    p = subprocess.run(["gcov", source_basename], cwd=str(work_dir),
                       capture_output=True, text=True)
    m = re.search(r"Lines executed:([\d.]+)% of \d+", p.stdout)
    return float(m.group(1)) if m else 0.0


@dataclass
class FuzzResult:
    found: bool
    kind: str                       # "crash" | "accepted" | "none"
    input: Optional[bytes]
    iterations: int
    coverage_history: List[float] = field(default_factory=list)


def black_box_fuzz(target, max_iterations: int = 20000, max_len: int = 32,
                   seed: int = 1, want: str = "accepted") -> FuzzResult:
    """Pure random: no feedback from the program (section 4.5)."""
    rng = random.Random(seed)
    hist: List[float] = []
    for i in range(1, max_iterations + 1):
        n = rng.randint(0, max_len)
        data = bytes(rng.randint(0, 255) for _ in range(n))
        rc, out, err = run_target(target.binary, data, target.work_dir)
        if is_crash(rc, err):
            return FuzzResult(True, "crash", data, i, hist)
        if want == "accepted" and _accepted(out):
            return FuzzResult(True, "accepted", data, i, hist)
    return FuzzResult(False, "none", None, max_iterations, hist)


def coverage_guided_fuzz(target, max_iterations: int = 2000,
                         max_len: int = 64, seed: int = 1,
                         seeds: Sequence[bytes] = (), measure_every: int = 1,
                         want: str = "accepted") -> FuzzResult:
    """Keep mutants that raise coverage and mutate from that corpus (section 4.6).

    Coverage is read from gcov; measure it every `measure_every` iterations to
    keep the run affordable."""
    rng = random.Random(seed)
    wd = Path(target.work_dir)
    reset_gcda(wd)

    corpus: List[bytes] = [bytes(s) for s in seeds] or [b"WSAC"]
    best = 0.0
    hist: List[float] = []

    for i in range(1, max_iterations + 1):
        base = bytearray(rng.choice(corpus))
        r = rng.random()
        if len(base) == 0:
            base.append(rng.randint(0, 255))
        elif r < 0.2 and len(base) < max_len:
            base.append(rng.randint(0, 255))            # grow
        elif r < 0.3 and len(base) > 1:
            del base[rng.randrange(len(base))]          # shrink
        else:
            base[rng.randrange(len(base))] = rng.randint(0, 255)   # flip
        cand = bytes(base)

        rc, out, err = run_target(target.binary, cand, wd)
        if is_crash(rc, err):
            return FuzzResult(True, "crash", cand, i, hist)
        if want == "accepted" and _accepted(out):
            return FuzzResult(True, "accepted", cand, i, hist)

        if i % measure_every == 0:
            cov = measure_coverage(target.source, wd)
            hist.append(cov)
            if cov > best:
                best = cov
                corpus.append(cand)     # keep the seed that reached new code

    return FuzzResult(False, "none", None, max_iterations, hist)

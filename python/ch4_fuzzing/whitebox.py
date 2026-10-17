"""White-box construction: use knowledge of the format (and optionally a solver)
to build an input directly, instead of guessing.

Two flavours:
  * structural : the format is known, so bytes are written straight away.
  * z3         : encode the parser's gate (magic/version are equalities) as
                 constraints and let Z3 solve for the bytes (the "use Z3 to
                 solve the magic number" approach from the assignment).
"""
from __future__ import annotations

import struct
import time
from typing import Tuple

from .seeds import MAGIC, header, record


def structural_gate() -> bytes:
    """A 12-byte header that passes the magic + version check (rc=0)."""
    return header(0)


def structural_deep(count: int = 1) -> bytes:
    """A header + records, reaching the record-parsing loop."""
    return header(count) + record(b"alice") * count


def structural_crash() -> bytes:
    """The off-by-one input (11 bytes): the vulnerable build reads one byte
    past the buffer -> ASan heap-buffer-overflow (CWE-193)."""
    return b"WSAC" + struct.pack("<HH", 1, 0) + b"\x01\x00\x00"


def z3_solve_gate() -> Tuple[bytes, float]:
    """Solve for the 6 header bytes (magic + version) with Z3.

    Returns (bytes, elapsed_seconds). Falls back to the known constant if z3
    is not installed."""
    t0 = time.perf_counter()
    try:
        from z3 import BitVec, Solver, sat
    except Exception:
        return MAGIC + struct.pack("<HH", 1, 0), time.perf_counter() - t0

    b = [BitVec(f"b{i}", 8) for i in range(6)]
    s = Solver()
    # The parser accepts iff memcmp(buf, "WSAC", 4) == 0 and version == 1.
    for i, ch in enumerate(b"WSAC"):
        s.add(b[i] == ch)
    s.add(b[4] == 1)     # version low byte
    s.add(b[5] == 0)     # version high byte
    if s.check() != sat:
        return b"", time.perf_counter() - t0
    m = s.model()
    out = bytes([m[b[i]].as_long() & 0xFF for i in range(6)])
    return out, time.perf_counter() - t0

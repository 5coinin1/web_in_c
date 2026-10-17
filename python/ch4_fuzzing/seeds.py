"""Seed corpus for the account-store parser.

A good seed corpus is what makes coverage-guided (white-box) fuzzing beat
black-box: seeds are already *near* the interesting branches, so the fuzzer
spends its budget exploring deeper instead of re-discovering the format from
noise. These seeds are built from the known format (magic WSAC + version +
count + 88-byte records), the "structural" knowledge a white-box has.
"""
from __future__ import annotations

import struct
from pathlib import Path
from typing import List

MAGIC = b"WSAC"


def header(count: int) -> bytes:
    # "WSAC" + version(u16=1) + reserved(u16=0) + count(u32, little-endian)
    return MAGIC + struct.pack("<HH", 1, 0) + struct.pack("<I", count)


def record(name: bytes = b"u") -> bytes:
    r = bytearray(88)                 # username[32] + salt[16] + hash[32] + created_at[8]
    r[0:len(name)] = name
    return bytes(r)


def seed_corpus() -> List[bytes]:
    return [
        b"",                          # empty
        b"WSAC",                      # magic only
        b"WSAC\x01\x00",              # magic + version
        header(0),                    # valid header, no records
        header(1),                    # header claiming 1 record, none present
        header(1) + record(b"alice"), # well-formed minimal store
        header(2) + record(b"alice") + record(b"bob"),
        b"WSAB" + struct.pack("<HH", 1, 0),   # one byte off the magic
        b"WSAC" + struct.pack("<HH", 2, 0),   # wrong version
        b"WSAC" + struct.pack("<HH", 1, 0) + b"\x01\x00\x00",  # 11-byte off-by-one
    ]


def write_seed_dir(path: str | Path) -> int:
    p = Path(path)
    p.mkdir(parents=True, exist_ok=True)
    seeds = seed_corpus()
    for i, s in enumerate(seeds):
        (p / f"seed_{i:02d}.dat").write_bytes(s)
    return len(seeds)

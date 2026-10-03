#!/usr/bin/env python3
"""Seed / edit the server's room store (server_data/rooms.dat) offline.

Rooms are created and deleted through the server console; this script only
produces the binary file the server loads at startup. No network access.

Binary format (must match src/room.c):
    magic "WSRM" | version u16=1 | reserved u16=0 | count u32
    count * record(name[32] + desc[160] + code[16], 208 bytes each)

Usage:
    python provision_rooms.py [rooms.json] [--out PATH] [--replace]
                             [--delete NAME ...]

    rooms.json   list of {"name","desc","code"} (optional; default built-in)
    --out        output file (default: server_data/rooms.dat)
    --replace    start from an empty store instead of merging
    --delete     delete a room by name (repeatable)

Examples:
    python provision_rooms.py
    python provision_rooms.py --replace my.json
    python provision_rooms.py --delete testroom
"""
import argparse
import json
import os
import struct
import sys

MAGIC = b"WSRM"
VERSION = 1
NAME_LEN, DESC_LEN, CODE_LEN = 32, 160, 16
RECORD_LEN = NAME_LEN + DESC_LEN + CODE_LEN   # 208

DEFAULT_ROOMS = [
    {"name": "general", "desc": "General chat for everyone", "code": ""},
    {"name": "gaming",  "desc": "Talk about video games",    "code": "1234"},
    {"name": "random",  "desc": "Off-topic and randomness",  "code": ""},
    {"name": "vip",     "desc": "Members only",              "code": "vip2026"},
    {"name": "help",    "desc": "Ask questions and get help", "code": ""},
]


def load_rooms(path):
    """Return an ordered dict {name: (desc, code)} from an existing store."""
    rooms = {}
    if not os.path.exists(path):
        return rooms
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 12 or data[:4] != MAGIC:
        return rooms
    count = struct.unpack_from("<I", data, 8)[0]
    off = 12
    for _ in range(count):
        if off + RECORD_LEN > len(data):
            break
        rec = data[off:off + RECORD_LEN]
        name = rec[0:NAME_LEN].split(b"\x00")[0].decode("utf-8", "replace")
        desc = rec[NAME_LEN:NAME_LEN + DESC_LEN].split(b"\x00")[0].decode("utf-8", "replace")
        code = rec[NAME_LEN + DESC_LEN:].split(b"\x00")[0].decode("utf-8", "replace")
        rooms[name] = (desc, code)
        off += RECORD_LEN
    return rooms


def save_rooms(path, rooms):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(MAGIC + struct.pack("<HH", VERSION, 0) + struct.pack("<I", len(rooms)))
        for name, (desc, code) in rooms.items():
            rec = bytearray(RECORD_LEN)
            rec[0:len(name)] = name.encode()[:NAME_LEN - 1]
            rec[NAME_LEN:NAME_LEN + len(desc)] = desc.encode()[:DESC_LEN - 1]
            rec[NAME_LEN + DESC_LEN:NAME_LEN + DESC_LEN + len(code)] = code.encode()[:CODE_LEN - 1]
            f.write(bytes(rec))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rooms_file", nargs="?", help="JSON file with room definitions")
    ap.add_argument("--out", default="server_data/rooms.dat")
    ap.add_argument("--replace", action="store_true", help="start from an empty store")
    ap.add_argument("--delete", action="append", default=[], metavar="NAME")
    args = ap.parse_args()

    if args.rooms_file:
        with open(args.rooms_file, "r", encoding="utf-8") as f:
            rooms_in = json.load(f)
    elif args.delete and not args.replace:
        rooms_in = []                 # delete-only
    else:
        rooms_in = DEFAULT_ROOMS

    rooms = {} if args.replace else load_rooms(args.out)

    for name in args.delete:
        if name in rooms:
            del rooms[name]
            print("  [-] deleted  : %s" % name)

    for r in rooms_in:
        name = r.get("name", "")
        if not name:
            continue
        if name in rooms:
            print("  [~] replaced : %s" % name)
        else:
            print("  [+] added    : %s" % name)
        rooms[name] = (r.get("desc", ""), r.get("code", ""))

    save_rooms(args.out, rooms)
    print("Wrote %d room(s) to '%s'" % (len(rooms), args.out))
    return 0


if __name__ == "__main__":
    sys.exit(main())

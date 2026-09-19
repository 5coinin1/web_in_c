#!/usr/bin/env python3
"""Provision chat rooms on the WebSocket server.

Connects to the server and issues CREATE_ROOM / DELETE_ROOM. The server
persists every change to server_data/rooms.dat, so rooms survive restarts.

Usage:
    python provision_rooms.py [rooms.json] [--host H] [--port P] [--admin KEY]
                             [--delete NAME ...] [--replace]

  rooms.json   JSON list of {"name","desc","code"} (optional; default built-in)
  --delete     delete a room by name (repeatable)
  --replace    delete ALL existing rooms, then create the list (full sync)

Examples:
    python provision_rooms.py                      # create default rooms
    python provision_rooms.py --replace my.json    # wipe then create from my.json
    python provision_rooms.py --delete testroom    # delete one room
"""
import argparse
import base64
import json
import os
import socket
import sys

DEFAULT_ROOMS = [
    {"name": "general", "desc": "General chat for everyone", "code": ""},
    {"name": "gaming",  "desc": "Talk about video games",    "code": "1234"},
    {"name": "random",  "desc": "Off-topic and randomness",  "code": ""},
    {"name": "vip",     "desc": "VIP members only",          "code": "vip2026"},
    {"name": "help",    "desc": "Ask questions and get help", "code": ""},
]


def ws_connect(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    key = base64.b64encode(os.urandom(16)).decode()
    req = ("GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n"
           "Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n"
           "Sec-WebSocket-Version: 13\r\n\r\n") % (host, port, key)
    s.send(req.encode())
    resp = s.recv(4096)
    if b"101" not in resp:
        raise RuntimeError("WebSocket handshake failed: %r" % resp[:80])
    return s


def ws_send(s, obj):
    data = json.dumps(obj).encode()
    mask = os.urandom(4)
    frame = bytearray([0x81])
    n = len(data)
    if n < 126:
        frame.append(0x80 | n)
    elif n < 65536:
        frame.append(0x80 | 126)
        frame.extend(n.to_bytes(2, "big"))
    else:
        frame.append(0x80 | 127)
        frame.extend(n.to_bytes(8, "big"))
    frame.extend(mask)
    for i, b in enumerate(data):
        frame.append(b ^ mask[i % 4])
    s.send(bytes(frame))


def ws_recv(s):
    d = s.recv(65536)
    if not d:
        return None
    ln = d[1] & 0x7F
    pos = 2
    if ln == 126:
        ln = int.from_bytes(d[2:4], "big")
        pos = 4
    elif ln == 127:
        ln = int.from_bytes(d[2:10], "big")
        pos = 10
    return d[pos:pos + ln].decode()


def request(s, obj):
    ws_send(s, obj)
    return ws_recv(s)


def list_rooms(s, admin):
    resp = request(s, {"type": "ROOMS", "admin": admin})
    try:
        return [r["name"] for r in json.loads(resp).get("rooms", [])]
    except Exception:
        return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rooms_file", nargs="?", help="JSON file with room definitions")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9090)
    ap.add_argument("--admin", default=os.environ.get("WSCHAT_ADMIN_KEY", "admin123"))
    ap.add_argument("--delete", action="append", default=[], metavar="NAME",
                    help="delete a room by name (repeatable)")
    ap.add_argument("--replace", action="store_true",
                    help="delete all existing rooms before creating the list")
    args = ap.parse_args()

    if args.rooms_file:
        with open(args.rooms_file, "r", encoding="utf-8") as f:
            rooms = json.load(f)
    elif args.delete and not args.replace:
        rooms = []                 # delete-only: do not re-create anything
    else:
        rooms = DEFAULT_ROOMS

    s = ws_connect(args.host, args.port)
    print("Connected to %s:%d" % (args.host, args.port))

    # Collect the set of rooms to delete
    to_delete = list(args.delete)
    if args.replace:
        existing = list_rooms(s, args.admin)
        to_delete.extend(existing)

    deleted = dfail = 0
    for name in to_delete:
        resp = request(s, {"type": "DELETE_ROOM", "admin": args.admin, "name": name})
        try:
            obj = json.loads(resp)
        except Exception:
            obj = {"type": "?", "raw": resp}
        if obj.get("type") == "ROOM_DELETED":
            print("  [-] deleted  : %s" % name)
            deleted += 1
        else:
            print("  [!] del fail : %s -> %s" % (name, obj.get("msg", obj)))
            dfail += 1

    ok = fail = 0
    for room in rooms:
        resp = request(s, {
            "type": "CREATE_ROOM",
            "admin": args.admin,
            "name": room.get("name", ""),
            "desc": room.get("desc", ""),
            "code": room.get("code", ""),
        })
        try:
            obj = json.loads(resp)
        except Exception:
            obj = {"type": "?", "raw": resp}
        if obj.get("type") == "ROOM_CREATED":
            print("  [+] created  : %s" % room.get("name"))
            ok += 1
        else:
            print("  [!] create fail: %s -> %s" % (room.get("name"), obj.get("msg", obj)))
            fail += 1

    s.close()
    print("Done: %d created, %d deleted (%d delete-fail, %d create-fail)"
          % (ok, deleted, dfail, fail))
    return 0 if (fail == 0 and dfail == 0) else 1


if __name__ == "__main__":
    sys.exit(main())

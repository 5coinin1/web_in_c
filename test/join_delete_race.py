"""
Stress the JOIN / DELETE_ROOM race.

room_join() releases room_lock before the caller applies
CLIENT_EVENT_JOIN_OK, so the console thread can delete the room in that
window. The failure mode this guards against is a client left in
STATE_IN_ROOM with an empty room name and no membership, where
  - JOIN is refused ("Leave your current room first"), and
  - LEAVE returns early on the empty name,
so the client can never recover.

The server must never leave a client in that state. The test therefore does
not try to hit the window deterministically; it hammers the race and then
asserts the observable consequence is absent: after every attempt each
client must still be able to join a stable room.
"""
import socket, os, base64, time, json, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090
ROUNDS = 60
CLIENTS = 3

_rbuf = {}


def conn():
    s = socket.socket(); s.settimeout(5); s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    s.send(('GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
            'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n' % key).encode())
    s.recv(4096)
    _rbuf[id(s)] = b""
    return s


def send(s, obj):
    data = json.dumps(obj).encode(); mask = os.urandom(4)
    f = bytearray([0x81]); n = len(data)
    if n < 126: f.append(0x80 | n)
    else: f.append(0x80 | 126); f.extend(n.to_bytes(2, 'big'))
    f.extend(mask)
    for i, b in enumerate(data): f.append(b ^ mask[i % 4])
    try: s.send(bytes(f))
    except Exception: pass


def _fill(s, timeout):
    s.settimeout(timeout)
    try:
        d = s.recv(65536)
        if d: _rbuf[id(s)] += d
    except Exception:
        pass
    finally:
        s.settimeout(5)


def recv(s, timeout=0.25):
    """Return the next frame as a dict, or None on timeout."""
    deadline = time.time() + timeout
    while True:
        b = _rbuf[id(s)]
        if len(b) >= 2:
            ln = b[1] & 0x7F; pos = 2
            if ln == 126:
                if len(b) >= 4:
                    ln = int.from_bytes(b[2:4], 'big'); pos = 4
                else:
                    ln = None
            if ln is not None and len(b) >= pos + ln:
                raw = b[pos:pos + ln]; _rbuf[id(s)] = b[pos + ln:]
                try: return json.loads(raw.decode())
                except Exception: return {'type': 'UNPARSEABLE'}
        if time.time() >= deadline:
            return None
        _fill(s, max(0.01, deadline - time.time()))


def collect(s, timeout=0.25):
    out = []
    while True:
        m = recv(s, timeout)
        if m is None: return out
        out.append(m)
        timeout = 0.08


def console(p, line):
    p.stdin.write(line + "\n"); p.stdin.flush()


def probe_recoverable(s, room):
    """Decide whether a 'Leave your current room first' reply is legitimate.

    A client that really joined the room is only being asked to leave first,
    so one LEAVE frees it. A STRANDED client sits in STATE_IN_ROOM with an
    empty room name, so LEAVE returns early, changes nothing, and the next
    JOIN is refused the same way forever.
    """
    send(s, {'type': 'LEAVE', 'room': room})
    collect(s, 0.25)
    send(s, {'type': 'JOIN', 'room': room, 'code': ''})
    for m in collect(s, 0.6):
        if m.get('type') == 'JOINED':
            send(s, {'type': 'LEAVE', 'room': room})
            collect(s, 0.25)
            return True
        if m.get('type') in ('JOIN_FAIL', 'ERROR'):
            if 'Leave your current room' in m.get('msg', ''):
                return False        # still stuck -> genuinely stranded
    return True


p = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, text=True)
time.sleep(1.5)

stranded = []
suspects = 0
try:
    console(p, 'room racer - target room')
    console(p, 'room safe - stable room')
    time.sleep(0.5)

    socks = []
    for i in range(CLIENTS):
        s = conn(); socks.append(s)
        send(s, {'type': 'REGISTER', 'username': 'race%d' % i, 'password': 'pw1234'})
        m = recv(s, 1.0)
        if not m or m.get('type') != 'REGISTER_OK':
            # already registered from a previous run
            send(s, {'type': 'LOGIN', 'username': 'race%d' % i, 'password': 'pw1234'})
            recv(s, 1.0)
        else:
            send(s, {'type': 'LOGIN', 'username': 'race%d' % i, 'password': 'pw1234'})
            recv(s, 1.0)

    for r in range(ROUNDS):
        for s in socks:
            send(s, {'type': 'JOIN', 'room': 'racer', 'code': ''})
        # Delete the room out from under the joins, then bring it back.
        console(p, 'del racer')
        console(p, 'room racer - target room')
        for s in socks:
            suspect = False
            for m in collect(s, 0.12):
                if m.get('type') == 'JOIN_FAIL' and 'Leave your current room' in m.get('msg', ''):
                    suspect = True
                if m.get('type') == 'ERROR' and 'Leave your current room' in m.get('msg', ''):
                    suspect = True
            if suspect:
                # Legitimate "you are in a room, leave first" is fine; only a
                # client that cannot get out at all is a stranding bug.
                suspects += 1
                if not probe_recoverable(s, 'racer'):
                    stranded.append((r, 'racer', 'unrecoverable after LEAVE'))
        if (r + 1) % 10 == 0:
            print('  round %d/%d' % (r + 1, ROUNDS), flush=True)

    # Liveness assertion: every client must still be able to join a room that
    # is not being deleted. A stranded client answers with
    # "Leave your current room first" instead of JOINED, no matter how often
    # it is asked - which is exactly why the probe above sends LEAVE first.
    print('\nfinal check: can each client still join a stable room?')
    for i, s in enumerate(socks):
        send(s, {'type': 'LEAVE', 'room': 'safe'})
        collect(s, 0.2)
        send(s, {'type': 'JOIN', 'room': 'safe', 'code': ''})
        got = None
        for m in collect(s, 0.6):
            if m.get('type') in ('JOINED', 'JOIN_FAIL', 'ERROR'):
                got = m; break
        ok = got is not None and got.get('type') == 'JOINED'
        print('  client %d: %s %s' % (i, 'OK' if ok else 'STRANDED',
                                      '' if ok else json.dumps(got)))
        if not ok:
            stranded.append(('final', 'safe', json.dumps(got)))
        else:
            send(s, {'type': 'LEAVE', 'room': 'safe'})
            collect(s, 0.2)

    for s in socks:
        s.close()

    print('\nrounds=%d clients=%d  "leave first" replies probed=%d'
          % (ROUNDS, CLIENTS, suspects))
    if stranded:
        print('RESULT: STRANDED CLIENT(S) DETECTED')
        for x in stranded[:10]:
            print('  ', x)
        raise SystemExit(1)
    print('RESULT: no stranded client (race handled)')
finally:
    console(p, 'quit')
    try: p.wait(timeout=3)
    except Exception: p.terminate()

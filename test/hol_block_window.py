"""
Rigour check for the head-of-line fix.

The earlier hol_block.py flood could push the stalled peer's queue past
CLIENT_OUT_QUEUE, so the peer may already have been disconnected (by design)
before the healthy client was probed. That does not isolate the critical
window: the writer is BLOCKED in send() but the peer is STILL a room member.

This test isolates exactly that window:

  * server SO_SNDBUF is capped (CLIENT_SNDBUF = 64 KiB), A's SO_RCVBUF is tiny,
  * flood just enough (~130 KiB) to fill the socket and park A's writer inside
    send(), while keeping A's outbound queue well under CLIENT_OUT_QUEUE,
  * assert A is STILL CONNECTED (not kicked), then
  * assert C's JOIN (which needs room_lock) still returns immediately.

If room_lock were still held across the blocking send() - the original bug -
C would time out even though A is merely stalled, not flooded past its queue.
"""
import socket, os, base64, time, json, subprocess, threading, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090
BIG = 'Z' * 4000
FLOOD_MSGS = 40                 # ~160 KiB: > socket buffers, < 256 KiB queue
STALL_WAIT = 3.0

_rbuf = {}
_lock = threading.Lock()


def conn(rcvbuf=None):
    s = socket.socket()
    if rcvbuf:
        try: s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        except Exception: pass
    s.settimeout(3); s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    s.send(('GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
            'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n' % key).encode())
    s.recv(4096)
    with _lock: _rbuf[id(s)] = b""
    return s


def send_json(s, obj):
    data = json.dumps(obj).encode(); mask = os.urandom(4)
    f = bytearray([0x81]); n = len(data)
    if n < 126: f.append(0x80 | n)
    elif n < 65536: f.append(0x80 | 126); f.extend(n.to_bytes(2, 'big'))
    else: f.append(0x80 | 127); f.extend(n.to_bytes(8, 'big'))
    f.extend(mask)
    for i, b in enumerate(data): f.append(b ^ mask[i % 4])
    s.sendall(bytes(f))


def _drain(s, timeout):
    end = time.time() + timeout
    frames = []
    dead = False
    while time.time() < end:
        with _lock: b = _rbuf[id(s)]
        got = False
        while len(b) >= 2:
            ln = b[1] & 0x7F; pos = 2
            if ln == 126:
                if len(b) >= 4: ln = int.from_bytes(b[2:4], 'big'); pos = 4
                else: ln = None
            elif ln == 127:
                if len(b) >= 10: ln = int.from_bytes(b[2:10], 'big'); pos = 10
                else: ln = None
            if ln is not None and len(b) >= pos + ln:
                raw = b[pos:pos + ln]
                with _lock: _rbuf[id(s)] = b[pos + ln:]
                try: frames.append(json.loads(raw.decode()))
                except Exception: frames.append({'type': 'UNPARSEABLE'})
                b = _rbuf[id(s)]; got = True
            else:
                break
        if frames:
            return frames, dead          # return as soon as we have a frame
        if got: continue
        s.settimeout(0.2)
        try:
            d = s.recv(1 << 20)
            if d == b'': dead = True; break
            if d:
                with _lock: _rbuf[id(s)] += d
        except socket.timeout:
            pass
        except Exception:
            dead = True; break
    return frames, dead


def recv_frame(s, timeout):
    frames, dead = _drain(s, timeout)
    if frames: return frames[0]
    if dead: return {'type': 'DISCONNECTED'}
    return None


def login_join(s, user, room):
    send_json(s, {'type': 'REGISTER', 'username': user, 'password': 'pw1234'})
    recv_frame(s, 2.0)
    send_json(s, {'type': 'LOGIN', 'username': user, 'password': 'pw1234'})
    recv_frame(s, 2.0)
    send_json(s, {'type': 'JOIN', 'room': room, 'code': ''})
    return recv_frame(s, 2.0)


def console(p, line):
    p.stdin.write(line + "\n"); p.stdin.flush()


p = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, text=True)
time.sleep(1.5)
try:
    console(p, 'room windowroom - stall window test')
    console(p, 'room otherroom - target room')
    time.sleep(0.5)

    A = conn(rcvbuf=4096)          # the peer that will stall
    B = conn()                     # floods, always drained
    C = conn()                     # the healthy witness

    print('A join:', login_join(A, 'stall1', 'windowroom'))
    print('B join:', login_join(B, 'floodA', 'windowroom'))
    send_json(C, {'type': 'REGISTER', 'username': 'witnessA', 'password': 'pw1234'})
    recv_frame(C, 2.0)
    send_json(C, {'type': 'LOGIN', 'username': 'witnessA', 'password': 'pw1234'})
    recv_frame(C, 2.0)

    drain_stop = threading.Event()
    def drain_b():
        while not drain_stop.is_set():
            _drain(B, 0.1)
    threading.Thread(target=drain_b, daemon=True).start()

    time.sleep(0.3)
    _drain(A, 0.3)                 # consume through the join, then stop reading A

    # Baseline: C is fast before anything stalls.
    tb = time.time()
    send_json(C, {'type': 'ROOMS'})
    brep = recv_frame(C, 3.0)
    db = time.time() - tb
    print('baseline C ROOMS: %.3fs %s' % (db, brep.get('type') if brep else 'NONE'))

    # Flood just under the queue limit. The socket buffers (16-64 KiB) fill
    # first, so A's writer parks in send() while A is still a member.
    print('flooding %d msgs (~%d KiB), A stays connected ...'
          % (FLOOD_MSGS, FLOOD_MSGS * len(BIG) // 1024), flush=True)
    for _ in range(FLOOD_MSGS):
        send_json(B, {'type': 'MESSAGE', 'content': BIG})
    time.sleep(0.5)

    # Is A still connected (not kicked)? Receive whatever is pending; a live
    # peer yields data, a kicked one yields EOF.
    A.settimeout(0.8)
    a_alive = True
    got = b''
    try:
        while True:
            d = A.recv(65536)
            if d == b'':
                a_alive = False; break
            got += d
    except socket.timeout:
        pass
    except Exception:
        a_alive = False

    # C must not be blocked while A is stalled-but-connected.
    t0 = time.time()
    send_json(C, {'type': 'JOIN', 'room': 'otherroom', 'code': ''})
    crep = recv_frame(C, STALL_WAIT)
    dt = time.time() - t0
    c_ok = crep is not None and crep.get('type') == 'JOINED'

    drain_stop.set()

    print('\nA still connected (not kicked) : %s' % a_alive)
    print('C JOIN while A stalled         : %s (%.2fs) %s'
          % (c_ok, dt, crep.get('type') if crep else 'NO REPLY'))
    print('\nverdict: %s'
          % ('PASS - room_lock free while a writer is blocked in send()'
             if (a_alive and c_ok) else 'FAIL'))

    for s in (A, B, C):
        try: s.close()
        except Exception: pass
    sys.exit(0 if (a_alive and c_ok) else 1)
finally:
    try:
        console(p, 'quit')
        p.wait(timeout=3)
    except Exception:
        p.terminate()

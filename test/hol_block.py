"""
Reproduce risk A: a blocked send() under the GLOBAL room_lock.

room_broadcast() holds room_lock while calling client_send_ws_text(), which
does a blocking send(). If ONE member stops reading, its TCP buffers fill,
the server thread blocks inside send() while still holding room_lock, and
every other room operation (JOIN/LEAVE/MESSAGE/create/delete, and the
console `list`) stalls behind it.

Shape of the test:
  A : joins the room, then STOPS reading, but keeps sending PING so the idle
      janitor cannot rescue the server. SO_RCVBUF is tiny to fill fast.
  B : floods the room with large MESSAGEs. One server thread sits in
      room_broadcast() until A's buffers are full, then blocks holding the
      lock.
  C : a healthy client that should be unaffected. While the lock is held it
      must get NO reply to a JOIN in another room.
  recovery: A drains its socket -> send() returns -> lock released -> C's
      JOIN is answered. This proves the stall was the lock, not a crash.
"""
import socket, os, base64, time, json, subprocess, threading, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090

BIG = 'X' * 4000            # one message payload, near MAX_MSG_LEN
NMSG = 500                  # ~2 MB: comfortably past any default snd/rcv buffers
STALL_WAIT = 4.0            # how long C waits before we call it "blocked"

_rbuf = {}
_lock = threading.Lock()


def conn(rcvbuf=None):
    s = socket.socket()
    if rcvbuf:
        try: s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        except Exception: pass
    s.settimeout(5); s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    s.send(('GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
            'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n' % key).encode())
    s.recv(4096)
    with _lock:
        _rbuf[id(s)] = b""
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


def _pump(s, timeout):
    s.settimeout(timeout)
    try:
        d = s.recv(1 << 20)
        if d:
            with _lock: _rbuf[id(s)] += d
            return len(d)
    except Exception:
        pass
    finally:
        s.settimeout(5)
    return 0


def recv_frame(s, timeout):
    deadline = time.time() + timeout
    while True:
        with _lock: b = _rbuf[id(s)]
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
                try: return json.loads(raw.decode())
                except Exception: return {'type': 'UNPARSEABLE'}
        left = deadline - time.time()
        if left <= 0: return None
        _pump(s, min(0.3, left))


def login_join(s, user, room):
    send_json(s, {'type': 'LOGIN', 'username': user, 'password': 'pw1234'})
    recv_frame(s, 2.0)
    send_json(s, {'type': 'JOIN', 'room': room, 'code': ''})
    return recv_frame(s, 2.0)


def console(p, line):
    p.stdin.write(line + "\n"); p.stdin.flush()


# ---- server, with stdout captured so we can see the console stall ----
lines = []
p = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                     stderr=subprocess.STDOUT, text=True, bufsize=1)


def stdout_reader():
    for ln in p.stdout:
        lines.append((time.time(), ln.rstrip()))
threading.Thread(target=stdout_reader, daemon=True).start()

time.sleep(1.5)
console(p, 'room general - test room')
console(p, 'room other - second room')
time.sleep(0.6)

try:
    A = conn(rcvbuf=4096)
    B = conn()
    C = conn()

    for nm, s in (('raceA', A), ('raceB', B), ('raceC', C)):
        send_json(s, {'type': 'REGISTER', 'username': nm, 'password': 'pw1234'})
        m = recv_frame(s, 2.0)
        if not m or m.get('type') != 'REGISTER_OK':
            send_json(s, {'type': 'LOGIN', 'username': nm, 'password': 'pw1234'})
            recv_frame(s, 2.0)

    print('A join:', login_join(A, 'raceA', 'general'))
    print('B join:', login_join(B, 'raceB', 'general'))
    # C logs in but stays out of the room
    send_json(C, {'type': 'LOGIN', 'username': 'raceC', 'password': 'pw1234'})
    recv_frame(C, 2.0)
    # A is now clients[0]; drain A up to the join, then stop reading.
    time.sleep(0.3)
    while recv_frame(A, 0.2): pass

    a_stop = threading.Event()      # set => A drains (recovery)

    def a_keepalive():
        while not a_stop.is_set():
            # keep last_active fresh WITHOUT reading, defeating the janitor
            try: send_json(A, {'type': 'PING'})
            except Exception: return
            for _ in range(20):
                if a_stop.is_set(): return
                time.sleep(0.5)
    threading.Thread(target=a_keepalive, daemon=True).start()

    def b_reader():                 # B must drain or its own send blocks early
        while True:
            if recv_frame(B, 0.3) is None and b_done.is_set(): return
    b_done = threading.Event()

    def b_flood():
        for _ in range(NMSG):
            try: send_json(B, {'type': 'MESSAGE', 'content': BIG})
            except Exception: break
        b_done.set()

    threading.Thread(target=b_reader, daemon=True).start()
    threading.Thread(target=b_flood, daemon=True).start()

    print('flooding %d x %d bytes ...' % (NMSG, len(BIG)), flush=True)
    time.sleep(2.5)                 # let A's buffers fill and the lock jam

    # ---- test 1: healthy client C cannot JOIN another room ----
    t0 = time.time()
    send_json(C, {'type': 'JOIN', 'room': 'other', 'code': ''})
    reply = recv_frame(C, STALL_WAIT)
    dt = time.time() - t0
    blocked = reply is None
    print('\n[C] JOIN another room -> %s after %.2fs'
          % (json.dumps(reply) if reply else 'NO REPLY', dt))

    # ---- test 2: a functional probe of room_lock, not stdout scraping ----
    # ROOMS -> room_list_json() takes room_lock, exactly like the console
    # `list`. Using a real client makes this deterministic, unlike reading the
    # server's stdout through a pipe that the flood may be filling.
    t2 = time.time()
    send_json(C, {'type': 'ROOMS'})
    rooms_reply = recv_frame(C, STALL_WAIT)
    dt2 = time.time() - t2
    console_blocked = rooms_reply is None
    print('[C] ROOMS (needs room_lock) -> %s after %.2fs'
          % (rooms_reply.get('type') if rooms_reply else 'NO REPLY', dt2))

    # ---- recovery ----
    print('\nrecovery: A starts reading its socket ...', flush=True)
    a_stop.set()

    def a_drain():
        end = time.time() + 12
        while time.time() < end:
            _pump(A, 0.3)
    threading.Thread(target=a_drain, daemon=True).start()
    time.sleep(2.0)
    # C may already be in 'other' from the test above; leave first so the
    # probe JOIN is a fresh attempt.
    send_json(C, {'type': 'LEAVE', 'room': 'other'})
    recv_frame(C, 1.0)
    send_json(C, {'type': 'JOIN', 'room': 'other', 'code': ''})
    after = recv_frame(C, 5.0)
    print('[C] JOIN after recovery -> %s'
          % (json.dumps(after) if after else 'STILL NO REPLY'))

    print('\n=== verdict ===')
    print('A reproduced (C blocked while A stalled) : %s' % blocked)
    print('console also blocked                     : %s' % console_blocked)
    print('C answered while A was stalled           : %s' % (not blocked))
    print('recovered after A resumed reading        : %s'
          % (after is not None and after.get('type') == 'JOINED'))
    # The fix makes C succeed immediately while A is stalled. Before the fix
    # the same test reported NO REPLY (blocked) and a stalled console.
    sys.exit(0 if (not blocked and not console_blocked
                   and after is not None and after.get('type') == 'JOINED') else 1)
finally:
    try:
        console(p, 'quit')
        p.wait(timeout=3)
    except Exception:
        p.terminate()

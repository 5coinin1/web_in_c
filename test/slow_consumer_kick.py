"""
Slow-consumer policy: a peer that never reads must be disconnected, not
allowed to grow the server's per-client queue without bound.

The writer thread copies frames into a fixed CLIENT_OUT_QUEUE (256 KiB) ring
buffer. A stalled peer's writer parks in a bounded send() (SO_SNDTIMEO), so the
queue fills; the next enqueue over the limit marks the client for kick and the
writer shuts the socket down.

Assertions (all with hard deadlines):
  1. the slow peer IS disconnected,
  2. a brand-new client can still connect, log in and read the room list
     afterwards, proving the server stayed healthy (it did not grow RAM, hang,
     or lose its global state).
"""
import socket, os, base64, time, json, subprocess, threading, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090
BIG = 'Y' * 4000
DEADLINE = 20.0

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


def drain(s, timeout):
    """Read whatever is available; return list of decoded frames."""
    out = []
    end = time.time() + timeout
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
                try: out.append(json.loads(raw.decode()))
                except Exception: out.append({'type': 'UNPARSEABLE'})
                b = _rbuf[id(s)]; got = True
            else:
                break
        if got: continue
        s.settimeout(0.2)
        try:
            d = s.recv(1 << 20)
            if d == b'': return out, True          # peer closed
            if d:
                with _lock: _rbuf[id(s)] += d
        except socket.timeout:
            pass
        except Exception:
            return out, True
    return out, False


def recv_frame(s, timeout, confirm_dead=False):
    frames, dead = drain(s, timeout)
    if frames: return frames[0]
    if dead: return {'type': 'DISCONNECTED'}
    if confirm_dead:
        s.settimeout(0.5)
        try:
            if s.recv(65536) == b'': return {'type': 'DISCONNECTED'}
        except Exception:
            return {'type': 'DISCONNECTED'}
    return None


def login_join(s, user, room):
    # REGISTER creates the account but does NOT authenticate; always LOGIN.
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
    console(p, 'room kickroom - slow consumer test')
    time.sleep(0.5)

    slow = conn(rcvbuf=4096)
    flooder = conn()
    print('slow join :', login_join(slow, 'slow1', 'kickroom'))
    print('flood join:', login_join(flooder, 'flood1', 'kickroom'))
    drain(slow, 0.3)                       # read up to the join, then stop

    # Background drainer for the flooder so it is never the slow one.
    stop = threading.Event()
    def drainer():
        while not stop.is_set():
            drain(flooder, 0.1)
    threading.Thread(target=drainer, daemon=True).start()

    print('flooding; slow peer will NOT read ...', flush=True)
    t0 = time.time()
    # IMPORTANT: never recv() on the slow socket during the flood - that would
    # drain it and it would stop being a slow consumer.
    for _ in range(3000):                  # ~12 MB, way past the 256 KiB queue
        send_json(flooder, {'type': 'MESSAGE', 'content': BIG})
    dt = time.time() - t0
    stop.set()

    # Now (and only now) drain the slow socket: if the server enforced
    # backpressure it has shut this connection down, so the drain ends in EOF.
    slow.settimeout(1.0)
    drained = 0
    kicked = False
    end = time.time() + 5.0
    while time.time() < end:
        try:
            d = slow.recv(65536)
            if d == b'':
                kicked = True
                break
            drained += len(d)
        except socket.timeout:
            break
        except Exception:
            kicked = True
            break

    # A brand-new client proves the server is still healthy.
    witness = conn()
    send_json(witness, {'type': 'REGISTER', 'username': 'wit1', 'password': 'pw1234'})
    recv_frame(witness, 2.0)
    send_json(witness, {'type': 'LOGIN', 'username': 'wit1', 'password': 'pw1234'})
    recv_frame(witness, 2.0)
    send_json(witness, {'type': 'ROOMS'})
    wrep = recv_frame(witness, 3.0)
    witness_ok = wrep is not None and wrep.get('type') == 'ROOM_LIST'

    print('\nslow peer disconnected : %s (flood %.1fs, drained %d bytes)'
          % (kicked, dt, drained))
    print('new client healthy     : %s (%s)'
          % (witness_ok, wrep.get('type') if wrep else 'NO REPLY'))

    for s in (slow, flooder, witness):
        try: s.close()
        except Exception: pass
    sys.exit(0 if (kicked and witness_ok) else 1)
finally:
    try:
        console(p, 'quit')
        p.wait(timeout=3)
    except Exception:
        p.terminate()

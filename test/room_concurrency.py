"""
Concurrency stress for the per-room locking change (problem H).

Many clients join/leave/message across several rooms while the console
creates and deletes rooms at the same time. This exercises the lock ordering
(list_lock -> room->lock) and the room lifetime (refcount) paths.

What it checks:
  * the server never deadlocks: after the stress a fresh client can still log
    in and list rooms within a short deadline,
  * the server exits cleanly on quit (no hang).
A deadlock or a use-after-free would make the fresh probe time out or the
server fail to exit.
"""
import socket, os, base64, time, json, subprocess, threading, random, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090
NROOMS = 6
NCLIENTS = 8
DURATION = 4.0

_rbuf = {}
_lock = threading.Lock()


def conn():
    s = socket.socket(); s.settimeout(5); s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    s.send(('GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
            'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n' % key).encode())
    s.recv(4096)
    with _lock: _rbuf[id(s)] = b""
    return s


def send(s, obj):
    data = json.dumps(obj).encode(); mask = os.urandom(4)
    f = bytearray([0x81]); n = len(data)
    if n < 126: f.append(0x80 | n)
    else: f.append(0x80 | 126); f.extend(n.to_bytes(2, 'big'))
    f.extend(mask)
    for i, b in enumerate(data): f.append(b ^ mask[i % 4])
    try: s.sendall(bytes(f))
    except Exception: pass


def drain(s, timeout):
    frames = []
    end = time.time() + timeout
    while time.time() < end:
        with _lock: b = _rbuf[id(s)]
        while len(b) >= 2:
            ln = b[1] & 0x7F; pos = 2
            if ln == 126:
                if len(b) >= 4: ln = int.from_bytes(b[2:4], 'big'); pos = 4
                else: ln = None
            if ln is not None and len(b) >= pos + ln:
                raw = b[pos:pos + ln]
                with _lock: _rbuf[id(s)] = b[pos + ln:]
                try: frames.append(json.loads(raw.decode()))
                except Exception: pass
                b = _rbuf[id(s)]
            else:
                break
        if frames: break
        s.settimeout(0.2)
        try:
            d = s.recv(1 << 20)
            if not d: break
            with _lock: _rbuf[id(s)] += d
        except socket.timeout:
            pass
        except Exception:
            break
    return frames


def wait_type(s, want, timeout):
    end = time.time() + timeout
    while time.time() < end:
        for m in drain(s, max(0.05, end - time.time())):
            if m.get('type') in want: return m
    return None


def client_thread(idx, stop):
    try:
        s = conn()
    except Exception:
        return
    u = 'cc%d' % idx
    send(s, {'type': 'REGISTER', 'username': u, 'password': 'pw1234'})
    wait_type(s, {'REGISTER_OK', 'REGISTER_FAIL'}, 2.0)
    send(s, {'type': 'LOGIN', 'username': u, 'password': 'pw1234'})
    if not wait_type(s, {'LOGIN_OK'}, 2.0):
        s.close(); return

    while not stop.is_set():
        room = 'ccroom%d' % random.randrange(NROOMS)
        send(s, {'type': 'JOIN', 'room': room, 'code': ''})
        rep = wait_type(s, {'JOINED', 'JOIN_FAIL', 'ROOM_CLOSED', 'DISCONNECTED'}, 2.0)
        if rep and rep.get('type') == 'JOINED':
            for _ in range(2):
                send(s, {'type': 'MESSAGE', 'content': 'hello from cc%d' % idx})
            time.sleep(0.02)
            send(s, {'type': 'LEAVE'})
            wait_type(s, {'LEFT'}, 1.0)
        else:
            time.sleep(0.02)
    try: s.close()
    except Exception: pass


def console_churn(srv, stop):
    i = 0
    while not stop.is_set():
        name = 'ccroom%d' % (i % NROOMS)
        srv.stdin.write('del %s\n' % name); srv.stdin.flush()
        time.sleep(0.03)
        srv.stdin.write('room %s - churn room %d\n' % (name, i)); srv.stdin.flush()
        i += 1
        time.sleep(0.05)


srv = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, text=True)
time.sleep(1.5)
stop = threading.Event()
try:
    for i in range(NROOMS):
        srv.stdin.write('room ccroom%d - churn room\n' % i)
    srv.stdin.flush()
    time.sleep(0.4)

    churn = threading.Thread(target=console_churn, args=(srv, stop), daemon=True)
    churn.start()
    threads = [threading.Thread(target=client_thread, args=(i, stop), daemon=True)
               for i in range(NCLIENTS)]
    for t in threads: t.start()

    time.sleep(DURATION)
    stop.set()
    for t in threads: t.join(timeout=2.0)
    churn.join(timeout=2.0)

    # Fresh probe: the server must still answer (no deadlock).
    ok = False
    try:
        s = conn()
        send(s, {'type': 'REGISTER', 'username': 'probe', 'password': 'pw1234'})
        wait_type(s, {'REGISTER_OK', 'REGISTER_FAIL'}, 2.0)
        send(s, {'type': 'LOGIN', 'username': 'probe', 'password': 'pw1234'})
        wait_type(s, {'LOGIN_OK'}, 2.0)
        send(s, {'type': 'ROOMS'})
        ok = wait_type(s, {'ROOM_LIST'}, 3.0) is not None
        s.close()
    except Exception:
        ok = False
    print('server responsive after stress :', ok)

    srv.stdin.write('quit\n'); srv.stdin.flush()
    try:
        rc = srv.wait(timeout=10)
    except subprocess.TimeoutExpired:
        rc = 'HANG'
    print('server exit                    :', rc)
    print('RESULT:', 'PASS' if (ok and rc == 0) else 'FAIL')
    sys.exit(0 if (ok and rc == 0) else 1)
finally:
    try: srv.terminate()
    except Exception: pass

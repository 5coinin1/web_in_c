import socket, os, base64, time, json, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090
_rbuf = {}


def conn():
    s = socket.socket(); s.settimeout(5); s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    s.send(('GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
            'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n' % key).encode())
    s.recv(4096); _rbuf[id(s)] = b""; return s


def send(s, obj):
    data = json.dumps(obj).encode(); mask = os.urandom(4)
    f = bytearray([0x81]); n = len(data)
    if n < 126: f.append(0x80 | n)
    else: f.append(0x80 | 126); f.extend(n.to_bytes(2, 'big'))
    f.extend(mask)
    for i, b in enumerate(data): f.append(b ^ mask[i % 4])
    s.send(bytes(f))


def recv(s):
    b = _rbuf[id(s)]
    while True:
        while len(b) >= 2:
            ln = b[1] & 0x7F; pos = 2
            if ln == 126:
                if len(b) < 4: break
                ln = int.from_bytes(b[2:4], 'big'); pos = 4
            if len(b) < pos + ln: break
            msg = b[pos:pos + ln].decode(); _rbuf[id(s)] = b[pos + ln:]
            return msg
        d = s.recv(65536)
        if not d: return None
        b += d; _rbuf[id(s)] = b


def login_join(s, u, pw):
    # Self-contained: REGISTER first (ignored if the account already exists),
    # then LOGIN. REGISTER does not authenticate by itself.
    send(s, {'type': 'REGISTER', 'username': u, 'password': pw}); time.sleep(0.2); recv(s)
    send(s, {'type': 'LOGIN', 'username': u, 'password': pw}); time.sleep(0.3); recv(s)
    send(s, {'type': 'JOIN', 'room': 'general'}); time.sleep(0.3); recv(s)


def drain(s):
    s.settimeout(0.4)
    try:
        while True:
            if recv(s) is None: break
    except Exception:
        pass
    s.settimeout(5)


p = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, text=True)
time.sleep(1.5)
try:
    # Self-contained: make sure the room exists (rooms are not seeded).
    p.stdin.write('room general - self test room\n'); p.stdin.flush()
    time.sleep(0.5)

    a = conn(); login_join(a, 'alice', 'secret123')
    b = conn(); login_join(b, 'bob', 'hunter2')
    time.sleep(0.3); drain(a); drain(b)   # drain join notifications

    tricky = 'he said "hi" \\ path\nline2\ttab'
    send(a, {'type': 'MESSAGE', 'content': tricky})
    time.sleep(0.3)
    raw = recv(b)
    print('raw frame :', raw)
    try:
        obj = json.loads(raw)
        ok = (obj.get('content') == tricky)
        print('parsed    :', repr(obj.get('content')))
        print('MATCH     :', ok)
    except Exception as e:
        print('json.loads FAILED:', e)

    a.close(); b.close()
finally:
    p.stdin.write('quit\n'); p.stdin.flush()
    try: p.wait(timeout=3)
    except Exception: p.terminate()
print('OK')

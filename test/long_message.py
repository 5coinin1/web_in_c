"""
Problem D: the client used to read MESSAGE content into a 512-byte buffer, so
any message longer than that was silently truncated even though the protocol
allows MAX_MSG_LEN (4096).

This drives the real C client in plain (piped) mode, has another client send a
~4000-byte message, and checks the C client printed the message's tail - i.e.
nothing past byte 512 was dropped.
"""
import socket, os, base64, time, json, subprocess, threading, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
CLIENT = os.path.join(ROOT, 'build', 'wschat_client.exe')
HOST, PORT = '127.0.0.1', 9090

CONTENT = 'A' * 3970 + 'ZZENDMARKER_0123456789_ABCDEF'   # 4000 bytes total

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
    elif n < 65536: f.append(0x80 | 126); f.extend(n.to_bytes(2, 'big'))
    else: f.append(0x80 | 127); f.extend(n.to_bytes(8, 'big'))
    f.extend(mask)
    for i, b in enumerate(data): f.append(b ^ mask[i % 4])
    s.sendall(bytes(f))


def recv(s, timeout=2.0):
    s.settimeout(timeout)
    try:
        d = s.recv(1 << 20)
    except Exception:
        return None
    if not d: return None
    ln = d[1] & 0x7F; pos = 2
    if ln == 126: ln = int.from_bytes(d[2:4], 'big'); pos = 4
    elif ln == 127: ln = int.from_bytes(d[2:10], 'big'); pos = 10
    try: return json.loads(d[pos:pos + ln].decode())
    except Exception: return {'type': 'UNPARSEABLE'}


p = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, text=True)
time.sleep(1.5)
try:
    p.stdin.write('room longroom - long message test\n'); p.stdin.flush()
    time.sleep(0.5)

    # The C client runs in plain mode (stdin is a pipe), joins 'longroom'.
    bob = subprocess.Popen([CLIENT, 'bob', 'hunter2', 'longroom'],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, bufsize=1)
    bob_out = []
    threading.Thread(target=lambda: [bob_out.append(l) for l in bob.stdout],
                     daemon=True).start()
    time.sleep(1.5)

    # alice sends a ~4000-byte message.
    a = conn()
    send(a, {'type': 'REGISTER', 'username': 'alice', 'password': 'secret123'}); recv(a)
    send(a, {'type': 'LOGIN', 'username': 'alice', 'password': 'secret123'}); recv(a)
    send(a, {'type': 'JOIN', 'room': 'longroom', 'code': ''}); recv(a)
    send(a, {'type': 'MESSAGE', 'content': CONTENT})
    time.sleep(1.0)

    joined = ''.join(bob_out)
    has_tail = 'ZZENDMARKER_0123456789_ABCDEF' in joined
    # The whole 4000-byte body should be present, not cut at 512.
    has_full = ('A' * 3970) in joined

    print('message bytes sent     :', len(CONTENT))
    print('C client saw tail      :', has_tail)
    print('C client saw full body :', has_full)
    try: bob.stdin.write('/exit\n'); bob.stdin.flush()
    except Exception: pass
    time.sleep(0.3); bob.terminate(); a.close()
    sys.exit(0 if has_tail else 1)
finally:
    try:
        p.stdin.write('quit\n'); p.stdin.flush(); p.wait(timeout=3)
    except Exception:
        p.terminate()

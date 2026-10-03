import socket, os, base64, time, json, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090


def start_server():
    p = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                         stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, text=True)
    time.sleep(1.2)
    return p


def console(p, line):
    p.stdin.write(line + "\n")
    p.stdin.flush()
    time.sleep(0.4)


def conn():
    s = socket.socket(); s.settimeout(5); s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    s.send(('GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n'
            'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
            'Sec-WebSocket-Version: 13\r\n\r\n' % (HOST, PORT, key)).encode())
    s.recv(4096)
    return s


def send(s, obj):
    data = json.dumps(obj).encode(); mask = os.urandom(4)
    f = bytearray([0x81]); n = len(data)
    if n < 126: f.append(0x80 | n)
    else: f.append(0x80 | 126); f.extend(n.to_bytes(2, 'big'))
    f.extend(mask)
    for i, b in enumerate(data): f.append(b ^ mask[i % 4])
    s.send(bytes(f))


_rbuf = b""


def recv(s):
    """Buffered frame reader (handles coalesced/partial frames)."""
    global _rbuf
    while True:
        while len(_rbuf) >= 2:
            ln = _rbuf[1] & 0x7F; pos = 2
            if ln == 126:
                if len(_rbuf) < 4: break
                ln = int.from_bytes(_rbuf[2:4], 'big'); pos = 4
            elif ln == 127:
                if len(_rbuf) < 10: break
                ln = int.from_bytes(_rbuf[2:10], 'big'); pos = 10
            if len(_rbuf) < pos + ln: break
            msg = _rbuf[pos:pos + ln].decode()
            _rbuf = _rbuf[pos + ln:]
            return msg
        d = s.recv(65536)
        if not d:
            return None
        _rbuf += d


p = start_server()
try:
    a = conn()
    send(a, {'type': 'LOGIN', 'username': 'alice', 'password': 'secret123'})
    time.sleep(0.3); print('login   :', recv(a))

    console(p, 'room temp - temporary room')          # create via server console
    send(a, {'type': 'JOIN', 'room': 'temp'}); time.sleep(0.3)
    print('join    :', recv(a))

    console(p, 'del temp')                            # delete the room while joined
    print('evicted :', recv(a))                       # expect ROOM_CLOSED

    send(a, {'type': 'MESSAGE', 'content': 'are you there?'}); time.sleep(0.3)
    print('message :', recv(a))                       # expect "Not in a room"

    send(a, {'type': 'ROOMS'}); time.sleep(0.3)
    print('rooms   :', recv(a)[:60], '...')           # still allowed (AUTHENTICATED)

    a.close()
finally:
    console(p, 'quit')
    try: p.wait(timeout=3)
    except Exception: p.terminate()
print('OK')

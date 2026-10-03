import socket, os, base64, time, json, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090


def build_frame(obj):
    data = json.dumps(obj).encode(); mask = os.urandom(4)
    f = bytearray([0x81]); n = len(data)
    if n < 126: f.append(0x80 | n)
    else: f.append(0x80 | 126); f.extend(n.to_bytes(2, 'big'))
    f.extend(mask)
    for i, b in enumerate(data): f.append(b ^ mask[i % 4])
    return bytes(f)


p = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, text=True)
time.sleep(1.5)
try:
    s = socket.socket(); s.settimeout(5); s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    http = ('GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
            'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n' % key).encode()

    # Pipelined: handshake + a WS frame in ONE TCP segment.
    frame = build_frame({'type': 'JOIN', 'room': 'general'})
    s.send(http + frame)

    resp = s.recv(65536)
    print('handshake 101:', b'101 Switching Protocols' in resp)

    d = s.recv(65536)                     # the pipelined frame's reply
    ln = d[1] & 0x7F; pos = 2
    if ln == 126: ln = int.from_bytes(d[2:4], 'big'); pos = 4
    print('pipelined reply:', d[pos:pos + ln].decode())
    s.close()
finally:
    p.stdin.write('quit\n'); p.stdin.flush()
    try: p.wait(timeout=3)
    except Exception: p.terminate()
print('OK')

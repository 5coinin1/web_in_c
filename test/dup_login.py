import socket, os, base64, time, json

HOST, PORT = '127.0.0.1', 9090

def conn():
    s = socket.socket(); s.settimeout(3); s.connect((HOST, PORT))
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

def recv(s):
    d = s.recv(65536)
    ln = d[1] & 0x7F; pos = 2
    if ln == 126: ln = int.from_bytes(d[2:4], 'big'); pos = 4
    return d[pos:pos+ln].decode()

a = conn(); send(a, {'type': 'LOGIN', 'username': 'alice', 'password': 'secret123'})
time.sleep(0.3); print('client A:', recv(a))

b = conn(); send(b, {'type': 'LOGIN', 'username': 'alice', 'password': 'secret123'})
time.sleep(0.3); print('client B:', recv(b))

send(a, {'type': 'JOIN', 'room': 'general'})
time.sleep(0.3); print('A join :', recv(a))

# B is rejected, but try to join anyway -> should be blocked
send(b, {'type': 'JOIN', 'room': 'general'})
time.sleep(0.3); print('B join :', recv(b))

a.close(); b.close()

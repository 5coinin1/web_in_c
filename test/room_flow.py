import socket, os, base64, time, json

HOST, PORT = '127.0.0.1', 9090

def conn(user, pw):
    s = socket.socket(); s.settimeout(3); s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    s.send(('GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n'
            'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
            'Sec-WebSocket-Version: 13\r\n\r\n' % (HOST, PORT, key)).encode())
    s.recv(4096)
    send(s, {'type': 'LOGIN', 'username': user, 'password': pw})
    time.sleep(0.2)
    print(user, 'login :', recv(s))
    return s

def send(s, obj):
    data = json.dumps(obj).encode(); mask = os.urandom(4)
    f = bytearray([0x81]); n = len(data)
    if n < 126: f.append(0x80 | n)
    elif n < 65536: f.append(0x80 | 126); f.extend(n.to_bytes(2, 'big'))
    else: f.append(0x80 | 127); f.extend(n.to_bytes(8, 'big'))
    f.extend(mask)
    for i, b in enumerate(data): f.append(b ^ mask[i % 4])
    s.send(bytes(f))

def recv(s):
    d = s.recv(65536)
    ln = d[1] & 0x7F; pos = 2
    if ln == 126: ln = int.from_bytes(d[2:4], 'big'); pos = 4
    elif ln == 127: ln = int.from_bytes(d[2:10], 'big'); pos = 10
    return d[pos:pos+ln].decode()

a = conn('alice', 'secret123')
send(a, {'type': 'ROOMS'}); time.sleep(0.2)
print('ROOM_LIST:', recv(a))

send(a, {'type': 'JOIN', 'room': 'gaming'}); time.sleep(0.2)
print('join gaming (no code) :', recv(a))

send(a, {'type': 'JOIN', 'room': 'gaming', 'code': '9999'}); time.sleep(0.2)
print('join gaming (bad code):', recv(a))

send(a, {'type': 'JOIN', 'room': 'gaming', 'code': '1234'}); time.sleep(0.2)
print('join gaming (good)    :', recv(a))

# Design: cannot JOIN another room while in one - must LEAVE first.
send(a, {'type': 'JOIN', 'room': 'vip', 'code': 'vip2026'}); time.sleep(0.2)
print('join vip while in room:', recv(a))

send(a, {'type': 'LEAVE'}); time.sleep(0.2)
print('leave gaming          :', recv(a))

send(a, {'type': 'JOIN', 'room': 'vip', 'code': 'vip2026'}); time.sleep(0.2)
print('join vip (good)       :', recv(a))

send(a, {'type': 'LEAVE'}); time.sleep(0.2)
recv(a)

send(a, {'type': 'JOIN', 'room': 'notexist'}); time.sleep(0.2)
print('join missing room     :', recv(a))

a.close()

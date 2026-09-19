import socket, os, base64, time, json, sys

HOST, PORT = '127.0.0.1', 9090

def connect(nick, room):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3)
    s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    req = ('GET / HTTP/1.1\r\nHost: %s:%d\r\nUpgrade: websocket\r\n'
           'Connection: Upgrade\r\nSec-WebSocket-Key: %s\r\n'
           'Sec-WebSocket-Version: 13\r\n\r\n') % (HOST, PORT, key)
    s.send(req.encode())
    s.recv(4096)
    ws_send(s, json.dumps({'type':'JOIN','room':room,'nickname':nick}))
    return s

def ws_send(s, msg):
    data = msg.encode()
    mask = os.urandom(4)
    frame = bytearray([0x81])
    n = len(data)
    if n < 126:
        frame.append(0x80 | n)
    elif n < 65536:
        frame.append(0x80 | 126); frame.extend(n.to_bytes(2,'big'))
    else:
        frame.append(0x80 | 127); frame.extend(n.to_bytes(8,'big'))
    frame.extend(mask)
    for i,b in enumerate(data):
        frame.append(b ^ mask[i%4])
    s.send(bytes(frame))

def ws_recv(s):
    try:
        data = s.recv(65536)
    except socket.timeout:
        return None
    if not data: return None
    length = data[1] & 0x7F
    pos = 2
    if length == 126: length = int.from_bytes(data[2:4],'big'); pos = 4
    elif length == 127: length = int.from_bytes(data[2:10],'big'); pos = 10
    return data[pos:pos+length].decode()

a = connect('Alice', 'general')
time.sleep(0.3)
print('Alice JOINED:', ws_recv(a))

b = connect('Bob', 'general')
time.sleep(0.3)
print('Bob JOINED  :', ws_recv(b))
print('Alice sees  :', ws_recv(a))

ws_send(a, json.dumps({'type':'MESSAGE','content':'Hello Bob!'}))
time.sleep(0.3)
print('Bob recv    :', ws_recv(b))

ws_send(b, json.dumps({'type':'MESSAGE','content':'Hi Alice!'}))
time.sleep(0.3)
print('Alice recv  :', ws_recv(a))

ws_send(a, json.dumps({'type':'LIST'}))
time.sleep(0.3)
print('LIST        :', ws_recv(a))

a.close(); b.close()
print('\n=== END-TO-END CHAT OK ===')

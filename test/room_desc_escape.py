import socket, os, base64, time, json, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090

p = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, text=True)
time.sleep(1.5)
try:
    # Admin-supplied description with JSON metacharacters
    tricky_desc = 'he said "hi" \\ here\ttab'
    p.stdin.write('room quoted - %s\n' % tricky_desc)
    p.stdin.flush(); time.sleep(0.6)

    s = socket.socket(); s.settimeout(5); s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    s.send(('GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
            'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n' % key).encode())
    s.recv(4096)

    def send(obj):
        data = json.dumps(obj).encode(); mask = os.urandom(4)
        f = bytearray([0x81]); n = len(data)
        if n < 126: f.append(0x80 | n)
        else: f.append(0x80 | 126); f.extend(n.to_bytes(2, 'big'))
        f.extend(mask)
        for i, b in enumerate(data): f.append(b ^ mask[i % 4])
        s.send(bytes(f))

    def recv():
        b = b''
        while True:
            while len(b) >= 2:
                ln = b[1] & 0x7F; pos = 2
                if ln == 126:
                    if len(b) < 4: break
                    ln = int.from_bytes(b[2:4], 'big'); pos = 4
                if len(b) < pos + ln: break
                return b[pos:pos + ln].decode()
            d = s.recv(65536)
            if not d: return None
            b += d

    send({'type': 'LOGIN', 'username': 'alice', 'password': 'secret123'}); time.sleep(0.3); recv()
    send({'type': 'ROOMS'}); time.sleep(0.4)
    raw = recv()
    try:
        obj = json.loads(raw)
        rooms = obj.get('rooms', [])
        hit = [r for r in rooms if r['name'] == 'quoted']
        print('json.loads  : OK, rooms =', len(rooms))
        if hit:
            got = hit[0]['desc']
            print('desc stored :', repr(got))
            print('MATCH       :', got == tricky_desc)
        else:
            print('MATCH       : False (room "quoted" missing)')
    except Exception as e:
        print('json.loads  : FAILED ->', e)

    p.stdin.write('del quoted\n'); p.stdin.flush(); time.sleep(0.4)
    s.close()
finally:
    p.stdin.write('quit\n'); p.stdin.flush()
    try: p.wait(timeout=3)
    except Exception: p.terminate()

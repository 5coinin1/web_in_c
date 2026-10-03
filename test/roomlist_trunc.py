"""
Room list pagination (problem G).

The server used to truncate the room list inside one ROOM_LIST frame and set a
"truncated" flag the client ignored, so with many rooms the menu silently
showed only part of them.

Now ROOMS takes an "offset" and each ROOM_LIST page reports "count" and
"has_more". This test creates more rooms than fit in one frame and pages
through them, checking:
  * every page is valid JSON,
  * the pages together return every room exactly once,
  * has_more is set until the last page.
"""
import socket, os, base64, time, json, subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090
NROOMS = 30
DESC = 'D' * 150                      # long desc so pages are byte-bounded

# Fresh store so the room count is exactly ours (the server re-seeds accounts).
for _f in ('accounts.dat', 'rooms.dat'):
    try: os.remove(os.path.join(ROOT, 'server_data', _f))
    except OSError: pass

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
    s.sendall(bytes(f))


def recv(s, timeout=2.0):
    s.settimeout(timeout)
    try: d = s.recv(1 << 20)
    except Exception: return None
    if not d: return None
    ln = d[1] & 0x7F; pos = 2
    if ln == 126: ln = int.from_bytes(d[2:4], 'big'); pos = 4
    try: return json.loads(d[pos:pos + ln].decode())
    except Exception: return {'type': 'UNPARSEABLE'}


p = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                     stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, text=True)
time.sleep(1.5)
try:
    for i in range(NROOMS):
        p.stdin.write('room pg%02d - %s\n' % (i, DESC))
    p.stdin.flush()
    time.sleep(1.0)

    s = conn()
    send(s, {'type': 'REGISTER', 'username': 'alice', 'password': 'secret123'}); recv(s)
    send(s, {'type': 'LOGIN', 'username': 'alice', 'password': 'secret123'}); recv(s)

    seen = []
    offset = 0
    pages = 0
    saw_more = False
    while True:
        send(s, {'type': 'ROOMS', 'offset': offset})
        rep = recv(s, 3.0)
        if not rep or rep.get('type') != 'ROOM_LIST':
            print('page error:', rep); break
        rooms = rep.get('rooms', [])
        count = rep.get('count', len(rooms))
        has_more = rep.get('has_more', False)
        pages += 1
        print('page %d: offset=%s count=%d has_more=%s'
              % (pages, rep.get('offset'), count, has_more))
        if len(rooms) != count:
            print('  WARN: count(%d) != rooms(%d)' % (count, len(rooms)))
        seen += [r['name'] for r in rooms]
        if has_more: saw_more = True
        if not has_more or count == 0: break
        offset += count

    uniq = set(seen)
    pg_seen = [x for x in seen if x.startswith('pg')]
    ok = (len(pg_seen) == NROOMS and len(set(pg_seen)) == NROOMS
          and saw_more and pages >= 2)
    print('\nrooms seen   :', len(seen))
    print('pg rooms     :', len(pg_seen), 'unique:', len(set(pg_seen)))
    print('pages        :', pages)
    print('saw has_more :', saw_more)

    for i in range(NROOMS):
        p.stdin.write('del pg%02d\n' % i)
    p.stdin.flush(); time.sleep(0.4)
    s.close()
    print('RESULT:', 'PASS' if ok else 'FAIL')
    import sys; sys.exit(0 if ok else 1)
finally:
    try:
        p.stdin.write('quit\n'); p.stdin.flush(); p.wait(timeout=3)
    except Exception:
        p.terminate()

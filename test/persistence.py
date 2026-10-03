"""
Durability / atomic save (problem I).

room_save_locked() and auth save_store() used to truncate the file in place
(fopen "wb") and rewrite it, so a crash mid-write left rooms.dat / accounts.dat
truncated -> all rooms/accounts lost. They now write to a temp file, fsync, and
rename over the target atomically.

Checks:
  1. clean restart: rooms and accounts persist, and no *.tmp file is left,
  2. hard kill (TerminateProcess) during rapid room creation: the data files
     are still loadable afterwards (server starts, answers ROOMS with valid
     JSON) - the original is never left corrupt.
"""
import socket, os, base64, time, json, subprocess, glob, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090
DATA = os.path.join(ROOT, 'server_data')

_rbuf = {}


def clean():
    for f in glob.glob(os.path.join(DATA, '*')):
        try: os.remove(f)
        except OSError: pass


def start():
    p = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                         stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, text=True)
    time.sleep(1.5)
    return p


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


def login_rooms(user):
    s = conn()
    send(s, {'type': 'REGISTER', 'username': user, 'password': 'pw1234'}); recv(s)
    send(s, {'type': 'LOGIN', 'username': user, 'password': 'pw1234'})
    lg = recv(s, 2.0)
    send(s, {'type': 'ROOMS'})
    rooms = recv(s, 2.0)
    s.close()
    return lg, rooms


# ---- Round 1: clean restart ----
clean()
srv = start()
srv.stdin.write('room r0 - a\nroom r1 - b\nroom r2 - c\nroom r3 - d\nroom r4 - e\n')
srv.stdin.flush(); time.sleep(0.6)
lg, _ = login_rooms('persist1')      # registers + logs in -> saves accounts
srv.stdin.write('quit\n'); srv.stdin.flush()
srv.wait(timeout=5)
tmps = glob.glob(os.path.join(DATA, '*.tmp'))
print('after clean shutdown, leftover *.tmp:', tmps if tmps else 'none')

srv = start()
lg, rooms = login_rooms('persist1')
n1 = len(rooms.get('rooms', [])) if rooms else -1
print('restart: login ok =', lg and lg.get('type') == 'LOGIN_OK', '| rooms =', n1)
srv.stdin.write('quit\n'); srv.stdin.flush(); srv.wait(timeout=5)
ok1 = (lg and lg.get('type') == 'LOGIN_OK' and n1 == 5 and not tmps)

# ---- Round 2: hard kill during rapid creation ----
clean()
srv = start()
lg, _ = login_rooms('persist2')
for i in range(40):
    srv.stdin.write('room k%02d - x\n' % i)
srv.stdin.flush()
time.sleep(0.2)
srv.terminate()                      # hard kill, possibly mid-save
try: srv.wait(timeout=5)
except Exception: pass

srv = start()
lg2, rooms2 = login_rooms('persist2')
n2 = len(rooms2.get('rooms', [])) if rooms2 else -1
valid = rooms2 is not None and rooms2.get('type') == 'ROOM_LIST'
print('after hard kill: login ok =', lg2 and lg2.get('type') == 'LOGIN_OK',
      '| ROOMS valid =', valid, '| rooms =', n2)
srv.stdin.write('quit\n'); srv.stdin.flush(); srv.wait(timeout=5)
ok2 = valid and (lg2 and lg2.get('type') == 'LOGIN_OK') and n2 > 0

print('\nRESULT:', 'PASS' if (ok1 and ok2) else 'FAIL')
sys.exit(0 if (ok1 and ok2) else 1)

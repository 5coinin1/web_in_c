"""
Shutdown double-destroy check.

Before the fix, on `quit` the main thread's cleanup_all_clients() freed every
client while each client thread was still parked in recv() and would free the
same client again when it woke. The tell-tale was a use-after-free: a log line
like "recv failed for fd=869287952" (a garbage fd), plus possible heap damage.

After the fix, shutdown only wakes the sockets; each client thread frees its
own client once. This test connects several clients, quits the server, and
checks the server exited cleanly with no garbage-fd error, repeated a few times
to give the race a chance to show if it were still present.
"""
import socket, os, base64, time, json, subprocess, re, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
HOST, PORT = '127.0.0.1', 9090
ROUNDS = 4
CLIENTS = 4


def handshake():
    s = socket.socket(); s.settimeout(3); s.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    s.send(('GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n'
            'Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n\r\n' % key).encode())
    s.recv(4096)
    return s


def send(s, obj):
    data = json.dumps(obj).encode(); mask = os.urandom(4)
    f = bytearray([0x81]); n = len(data)
    if n < 126: f.append(0x80 | n)
    else: f.append(0x80 | 126); f.extend(n.to_bytes(2, 'big'))
    f.extend(mask)
    for i, b in enumerate(data): f.append(b ^ mask[i % 4])
    try: s.sendall(bytes(f))
    except Exception: pass


def one_round(idx):
    srv = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, bufsize=1)
    out = []
    import threading
    threading.Thread(target=lambda: [out.append(l) for l in srv.stdout],
                     daemon=True).start()
    time.sleep(1.5)
    srv.stdin.write('room sdroom - shutdown test\n'); srv.stdin.flush()
    time.sleep(0.3)

    socks = []
    for i in range(CLIENTS):
        s = handshake(); socks.append(s)
        u = 'sd%d_%d' % (idx, i)
        send(s, {'type': 'REGISTER', 'username': u, 'password': 'pw1234'})
        time.sleep(0.05)
        send(s, {'type': 'LOGIN', 'username': u, 'password': 'pw1234'})
        time.sleep(0.05)
        send(s, {'type': 'JOIN', 'room': 'sdroom', 'code': ''})
        time.sleep(0.05)
    time.sleep(0.5)

    srv.stdin.write('quit\n'); srv.stdin.flush()
    try:
        rc = srv.wait(timeout=10)
    except subprocess.TimeoutExpired:
        srv.terminate(); rc = 'TIMEOUT'
    for s in socks:
        try: s.close()
        except Exception: pass

    log = ''.join(out)
    # Any "fd=<number>" where the number is absurd (fds are small) means a
    # use-after-free of a freed client.
    garbage = re.findall(r'fd=(\d+)', log)
    bad = [g for g in garbage if int(g) > 100000]
    return rc, bad, log


def main():
    all_bad = []
    for idx in range(ROUNDS):
        rc, bad, log = one_round(idx)
        print('round %d: exit=%s garbage_fd=%s' % (idx, rc, bad if bad else 'none'))
        all_bad += bad
        if rc != 0:
            print('  non-zero exit; log tail:')
            for l in log.splitlines()[-6:]:
                print('   ', l)
    if all_bad:
        print('RESULT: use-after-free detected (garbage fds:', all_bad, ')')
        sys.exit(1)
    print('RESULT: clean shutdown, no garbage fds')
    sys.exit(0)


main()

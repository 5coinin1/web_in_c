import subprocess, time, threading, sys, os

EXE = os.path.join(os.path.dirname(__file__), '..', 'build', 'wschat_client.exe')

def reader(name, p):
    for line in p.stdout:
        sys.stdout.write(f"[{name}] {line}")
        sys.stdout.flush()

def start(user, pw, room):
    p = subprocess.Popen([EXE, user, pw, room], stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         text=True, bufsize=1)
    threading.Thread(target=reader, args=(user, p), daemon=True).start()
    return p

alice = start('alice', 'secret123', 'general')
time.sleep(0.6)
bob = start('bob', 'hunter2', 'general')
time.sleep(0.6)

alice.stdin.write('Hello Bob!\n'); alice.stdin.flush()
time.sleep(0.4)
bob.stdin.write('Hi Alice, how are you?\n'); bob.stdin.flush()
time.sleep(0.4)
alice.stdin.write('/exit\n'); alice.stdin.flush()
time.sleep(0.4)
bob.stdin.write('bye\n'); bob.stdin.flush()
time.sleep(0.4)
bob.stdin.write('/exit\n'); bob.stdin.flush()
time.sleep(0.5)

alice.terminate(); bob.terminate()
print("\n=== DONE ===")

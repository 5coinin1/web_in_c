"""
Problem E: in plain (piped) mode the client quit the whole app when a JOIN was
refused, instead of returning to the room menu like the TTY path does.

The client is started with a room argument that does not exist. It must:
  * report that the room could not be joined,
  * fall back to the room menu,
  * and still be able to join a real room afterwards.
"""
import os, subprocess, time, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER = os.path.join(ROOT, 'build', 'wschat_server.exe')
CLIENT = os.path.join(ROOT, 'build', 'wschat_client.exe')

# Fresh store so the server seeds alice/bob and we control the room set.
for f in ('accounts.dat', 'rooms.dat'):
    p = os.path.join(ROOT, 'server_data', f)
    try: os.remove(p)
    except OSError: pass

srv = subprocess.Popen([SERVER], cwd=os.path.join(ROOT, 'build'),
                       stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, text=True)
time.sleep(1.5)
try:
    srv.stdin.write('room fallbackroom - only real room\n'); srv.stdin.flush()
    time.sleep(0.5)

    # Ask for a room that does not exist, then pick #1 from the menu and leave.
    cli = subprocess.Popen([CLIENT, 'bob', 'hunter2', 'nosuchroom'],
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, text=True, bufsize=1)
    out = []
    import threading
    threading.Thread(target=lambda: [out.append(l) for l in cli.stdout],
                     daemon=True).start()
    time.sleep(1.0)
    cli.stdin.write('1\n'); cli.stdin.flush()
    time.sleep(0.8)
    cli.stdin.write('/exit\n'); cli.stdin.flush()
    time.sleep(0.8)
    cli.terminate()

    text = ''.join(out)
    has_fallback = "Could not join 'nosuchroom'" in text
    has_menu = 'AVAILABLE ROOMS' in text
    has_join = 'Joined room' in text

    print('fallback message :', has_fallback)
    print('reached menu     :', has_menu)
    print('joined after     :', has_join)
    sys.exit(0 if (has_fallback and has_menu and has_join) else 1)
finally:
    try:
        srv.stdin.write('quit\n'); srv.stdin.flush(); srv.wait(timeout=3)
    except Exception:
        srv.terminate()

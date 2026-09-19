import struct, sys

path = sys.argv[1] if len(sys.argv) > 1 else 'server_data/accounts.db'
d = open(path, 'rb').read()

print('file       :', path)
print('magic      :', d[:4])
print('version    :', struct.unpack_from('<H', d, 4)[0])
print('count      :', struct.unpack_from('<I', d, 8)[0])
print('total size :', len(d), 'bytes')

off = 12
while off + 88 <= len(d):
    rec = d[off:off+88]
    name = rec[:32].split(b'\x00')[0].decode('utf-8', 'replace')
    salt = rec[32:48].hex()
    h = rec[48:80].hex()
    ts = struct.unpack_from('<q', rec, 80)[0]
    print(f'--- record ---')
    print(f'  username : {name!r} (plaintext)')
    print(f'  salt     : {salt}')
    print(f'  sha256   : {h}')
    print(f'  created  : {ts}')
    off += 88

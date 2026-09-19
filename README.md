# wschat

A small WebSocket chat server and console client written in C.

- HTTP Upgrade handshake + WebSocket framing (RFC 6455) implemented by hand
- Login / registration with salted SHA-256 password hashes
- Persisted rooms (created/deleted via the server console or the Python script)
- Full-screen terminal UI (chat pane + user list, login/register screens)
- Single active session per account

## Requirements

- CMake >= 3.21
- A C11 compiler
- OpenSSL (development headers + libraries)
- POSIX threads (winpthread on MinGW)

Install them per platform:

| Platform | Install |
|----------|---------|
| Windows (MSYS2 / MinGW-w64) | `pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl mingw-w64-x86_64-make` |
| Debian / Ubuntu | `sudo apt install build-essential cmake libssl-dev` |
| macOS (Homebrew) | `brew install cmake openssl` |

## Build

The build is driven by CMake presets.

Windows (MSYS2):

```sh
cmake --preset windows-mingw
cmake --build --preset windows-mingw
```

Linux / macOS (OpenSSL in a standard location):

```sh
cmake --preset default
cmake --build --preset default
```

If OpenSSL is somewhere non-standard, point CMake at it (do not edit the
CMakeLists):

```sh
cmake -DOPENSSL_ROOT_DIR=/path/to/openssl -DCMAKE_PREFIX_PATH=/path/to/prefix -B build
```

On Windows, if your MSYS2 is not installed at `C:/msys64`, edit the paths in
`CMakePresets.json` (preset `windows-mingw`).

## Run

Start the server (opens an admin console; type `help`):

```sh
./build/wschat_server
```

In another terminal, start a client:

```sh
./build/wschat_client            # interactive: login or register
./build/wschat_client alice secret123 general   # user password room
```

Default accounts (seeded on first run): `alice / secret123`, `bob / hunter2`.

## Rooms

Rooms are not hard-coded. Create/delete them from the server console:

```
room <name> <code|-> <description...>   create a room (- = no code)
del <name>                              delete a room
list                                    list rooms
```

or provision them from a script (useful for initial seed data):

```sh
python tools/provision_rooms.py                 # create the default rooms
python tools/provision_rooms.py --replace       # wipe then create
python tools/provision_rooms.py --delete test   # delete one room
```

Rooms are persisted to `server_data/rooms.dat`.

## Data layout

Server and client keep their data separate, next to the project root
(independently of the working directory):

- `server_data/accounts.dat` - accounts (username + salt + SHA-256 hash)
- `server_data/rooms.dat`    - room definitions
- `client_data/client.dat`   - last username / room used by the client

All three are custom binary formats (not SQLite) and are not encrypted.

## Injected vulnerabilities (for analysis)

The project ships **one target parser** with three intentionally injected bugs,
so the analysis modules have concrete material:

- **Ch2 (memory safety)** - bounds / overflow bugs
- **Ch3 (SMT)** - the `off = 12 + i * RECORD_SIZE` / `count` arithmetic
- **Ch4 (fuzzing)** - the `"WSAC"` magic + `count` + fixed-record layout

### Target

`auth_store_parse(const uint8_t *buf, size_t len)` in `src/auth.c` (declared in
`src/auth.h`). It parses the account store, whose layout is:

```
offset  size  field
0       4     magic "WSAC"
4       2     version (u16, must be 1)
6       2     reserved
8       4     count (u32)            <- file-controlled
12      88*N  records (fixed 88 bytes each)
```

`load_store()` reads the file into a buffer and calls this parser, so the same
buffer input can be driven from a fuzzer or reproduced by hand.

### Builds

| Target | Bug state | Purpose |
|--------|-----------|---------|
| `wschat_server` | fixed | normal server (must never crash on crafted data) |
| `wschat_server_vuln` | **vulnerable** | run the server with the bugs (-DVULN) |
| `wschat_fuzz_store` | fixed | parser harness, for before/after comparison |
| `wschat_fuzz_store_vuln` | **vulnerable** | parser harness used to find the bugs |

Add `-DWCHAT_SANITIZE=ON` (GCC/Clang on Linux/macOS) to build the two `_vuln`
targets with ASan/UBSan - this is what turns the silent overflows into
reported errors. On MinGW the sanitizer runtimes are not available, so the
`asan` preset is intended for Linux/macOS.

### The three bugs

| ID | Location | CWE | What is wrong |
|----|----------|-----|----------------|
| A | `src/auth.c:95` (fix) / `:108` (bug) | CWE-129 -> CWE-787 | `count` is used as a loop bound and to index `g_accounts[]` without being capped at `MAX_ACCOUNTS` (256), so a large `count` writes past the global array. |
| B | `src/auth.c:104` (fix) / `:110` (bug) | CWE-125, CWE-190 | The per-record bounds check is missing in `-DVULN`; `off` is not verified against `len`, so records are read past the end of the buffer. The naive check `off + RECORD_SIZE <= len` can also wrap - the fixed code uses subtraction. |
| C | `src/auth.c:82` (bug) | CWE-193 | The header length check is `len < 11` instead of `len < 12`, so an 11-byte store is accepted and `get_u32(buf + 8)` reads `buf[8..11]`, one byte past the end. |

### Reproduce

```sh
python tools/make_pocs.py pocs           # generate the crafted store files

# Vulnerable behaviour
build/wschat_fuzz_store_vuln pocs/poc_offbyone.dat   # crashes (CWE-193)
build/wschat_fuzz_store_vuln pocs/poc_count.dat      # accounts = 300 > 256 (CWE-787)
build/wschat_fuzz_store_vuln pocs/poc_short.dat      # OOB read (visible with ASan)

# Fixed behaviour (must not crash; results are bounded/clean)
build/wschat_fuzz_store pocs/poc_offbyone.dat        # rc = -1
build/wschat_fuzz_store pocs/poc_count.dat           # accounts = 256
build/wschat_fuzz_store pocs/poc_short.dat           # accounts = 0
```

With ASan, build `wschat_fuzz_store_vuln` via `-DWCHAT_SANITIZE=ON` and rerun -
A reports a `global-buffer-overflow`, B a `heap-buffer-overflow`, C an
out-of-bounds read.

### Suggested module mapping

- **Ch2**: run `cppcheck` / the memory-safety scanner on `src/auth.c`, then
  ASan on the `_vuln` harness with the PoCs; apply the `[FIX x]` branches and
  confirm with `wschat_fuzz_store`.
- **Ch3**: model `count`, `off = 12 + i * RECORD_SIZE` and `len` in Z3;
  prove `count <= MAX_ACCOUNTS && RECORD_SIZE <= len - off` is safe and let it
  return the counterexample when those constraints are dropped.
- **Ch4**: fuzz `auth_store_parse` black-box (random bytes must guess the 4-byte
  `"WSAC"` magic) vs white-box (Z3 solves the magic and the length conditions),
  and compare attempts/time.

> The parser is the single analysis target shared by Ch2/Ch3/Ch4. Ch1 (Kripke/BMC)
> is modelled separately on the connection state machine
> (`STATE_HTTP_HANDSHAKE -> STATE_WS_CONNECTED -> STATE_AUTHENTICATED -> STATE_IN_ROOM`).

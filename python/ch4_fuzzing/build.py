"""Build the Chapter-4 fuzz target.

Target   : auth_store_parse() in src/auth.c -- a binary parser with a 4-byte
           "WSAC" magic, a version, a count and fixed records (matches the
           "parser with a magic byte" theme of Chapter 4).
Harness  : test/fuzz_store.c (reads a file, calls the parser).

Two build modes matter:
  * coverage : gcc --coverage so gcov can report line coverage (white-box signal)
  * asan     : -fsanitize=address so out-of-bounds reads/writes abort reliably.
               ASan is NOT available on this MinGW toolchain; use WSL Ubuntu
               (or any Linux) to get the reliable oracle.

The parser uses no cryptography, and auth.c links SHA256/RAND_bytes anyway, so
stubs/ supplies tiny OpenSSL stubs to avoid a libssl-dev dependency.
"""
from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


def repo_root() -> Path:
    # .../<root>/python/ch4_fuzzing/build.py
    return Path(__file__).resolve().parents[2]


def work_dir() -> Path:
    d = Path(__file__).resolve().parent / "_work"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _run(cmd) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True)


def asan_available(cc: str = "gcc") -> bool:
    """True if the toolchain can compile+link a program with -fsanitize=address."""
    try:
        with tempfile.TemporaryDirectory() as t:
            src = Path(t) / "a.c"
            src.write_text("int main(void){int a[2];return a[3];}\n")
            exe = Path(t) / "a"
            r = _run([cc, "-fsanitize=address", str(src), "-o", str(exe)])
            return r.returncode == 0
    except Exception:
        return False


@dataclass
class Target:
    binary: Path
    work_dir: Path
    source: str          # basename used by gcov, e.g. "auth.c"
    asan: bool           # whether the binary was built with ASan


def build_target(vuln: bool = True, coverage: bool = True,
                 asan: bool | None = None, cc: str = "gcc") -> Target:
    root = repo_root()
    wd = work_dir()
    stubs = Path(__file__).resolve().parent / "stubs"

    if asan is None:
        asan = asan_available(cc)

    flags = ["-O0", "-g", f"-I{stubs}", f"-I{root / 'src'}"]
    if coverage:
        flags.insert(0, "--coverage")
    if vuln:
        flags.append("-DVULN")
    if asan:
        flags.append("-fsanitize=address")

    # Compile each unit separately so gcov names its notes files after the
    # source (auth.gcno) instead of after the output binary.
    sources = {
        "fuzz_store":   root / "test" / "fuzz_store.c",
        "auth":         root / "src" / "auth.c",
        "log":          root / "src" / "log.c",
        "stub_openssl": stubs / "stub_openssl.c",
    }
    objs = []
    for name, src in sources.items():
        obj = wd / f"{name}.o"
        cmd = [cc] + flags + ["-c", str(src), "-o", str(obj)]
        r = _run(cmd)
        if r.returncode != 0:
            raise RuntimeError(f"compile {name} failed:\n{r.stderr}")
        objs.append(str(obj))

    out = wd / ("target_vuln" if vuln else "target_fixed")
    link = [cc] + (["--coverage"] if coverage else []) \
                 + (["-fsanitize=address"] if asan else []) \
                 + ["-o", str(out)] + objs
    r = _run(link)
    if r.returncode != 0:
        raise RuntimeError(f"link failed:\n{r.stderr}")

    return Target(binary=out, work_dir=wd, source="auth.c", asan=asan)

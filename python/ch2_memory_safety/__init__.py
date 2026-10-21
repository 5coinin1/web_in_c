"""Chương 2 — Kiểm toán an toàn bộ nhớ C (Memory Safety Audit).

Target: ``auth_store_parse()`` trong ``src/auth.c`` — parser file account-store
(magic ``WSAC`` + version + ``count`` + record 88 byte).

Ba lỗi cố ý (bật bằng ``-DVULN``):
  * CWE-193 — header check ``len < 11`` (off-by-one)
  * CWE-787 — ``count`` không cap tại ``MAX_ACCOUNTS`` (ghi quá mảng)
  * CWE-125 — ``off`` không kiểm tra với ``len`` (đọc quá heap)

Công cụ:
  * ``static_check.py`` — cppcheck XML + pattern scanner
  * ``asan_runner.py``  — build ASan/UBSan (WSL) và chạy 3 PoC trên bản lỗi/vá
  * ``report.py``       — sinh ``docs/findings_ch2.md`` + bảng before/after
  * ``run_ch2.py``      — chạy cả 3 bước; trên Windows tự dispatch vào WSL

Chạy:
    py -3 python/ch2_memory_safety/run_ch2.py          # Windows -> WSL
    python3 python/ch2_memory_safety/run_ch2.py        # trong WSL/Linux
"""
from .pattern_scan import PatternFinding, scan_file
from .static_check import CppcheckReport, run_cppcheck

__all__ = [
    "PatternFinding",
    "scan_file",
    "CppcheckReport",
    "run_cppcheck",
]

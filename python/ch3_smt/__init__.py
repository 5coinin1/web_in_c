"""Chương 3 — Kiểm chứng bằng SMT / BMC (Z3).

Dùng Z3 để giải các ràng buộc số học của mã được phân tích (offset/index/
alignment), ví dụ `off = 12 + i*RECORD_SIZE` và biên `count` của parser
account-store (src/auth.c).

TODO (Ch3):
  * smt.py   : mã hoá nghĩa vụ (tràn số / biên mảng / alignment) cho Z3
  * checks.py: chứng minh an toàn hoặc sinh phản ví dụ; đề xuất ràng buộc
               input-validation để loại phản ví dụ
"""

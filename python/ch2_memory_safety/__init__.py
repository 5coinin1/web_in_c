"""Chương 2 — Kiểm toán an toàn bộ nhớ C (Memory Safety Audit).

Mã C ở src/: auth_store_parse() là parser được phân tích; các lỗ hổng *cố ý*
bật bằng -DVULN (CWE-193 / CWE-787 / CWE-125). Package này bọc các công cụ
phân tích tĩnh quanh mã đó.

TODO (Ch2):
  * static_check.py : chạy cppcheck + quét mẫu nguy hiểm (strcpy/memcpy/...)
  * report.py       : phân tích output ASan/UBSan (build dưới WSL) thành bảng
  * compare.py      : đối chiếu bản vá vs bản lỗi
"""

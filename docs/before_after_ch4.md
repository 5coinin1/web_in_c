# Bảng before/after — Chương 4

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-193 (CWE-125/787 liên quan) | `src/auth.c:122` / `src/bytes.h:30` | Fuzzing tìm crash: 11-byte store → ASan heap-buffer-overflow; coverage-guided seeded 17 lần, white-box 1 lần | Fixed build không crash; parser trả `-1`; fuzzing không tìm thấy crash | Fuzzer + ASan + gcov |

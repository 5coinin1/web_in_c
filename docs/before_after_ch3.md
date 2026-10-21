# Bảng before/after — Chương 3

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-193 | `src/read_buffer.h` (trước: `src/server.c:76-83`) | `L=4096,N=4096 → index=8192`; SMT SAT; harness `bad_index=true` | guard `N ≤ C-1-L`; SMT UNSAT; harness `accepted=false` | Z3 + C harness |
| CWE-190 | `src/read_buffer.h` | có nguy cơ tràn nếu miền không giới hạn | SMT UNSAT trong miền hợp lệ | Z3 |
| CWE-787 | `src/read_buffer.h` | ghi NUL tại index 8192 → quá mảng | index ≤ 8191 | Z3 + harness |

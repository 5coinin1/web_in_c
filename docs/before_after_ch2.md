# Bảng before/after — Chương 2

| CWE | Vị trí | Trạng thái v0 | Trạng thái v1 | Công cụ xác minh |
|---|---|---|---|---|
| CWE-193 | `src/auth.c:114` | 11-byte store được chấp nhận; ASan `heap-buffer-overflow` READ size 1 tại `src/bytes.h:30` (caller `src/auth.c:122`) | `len < 12`; parser trả `-1`, không ASan | ASan/UBSan + harness |
| CWE-787 | `src/auth.c:122-147` | `count=300` ghi quá `g_accounts[256]`; ASan `global-buffer-overflow` WRITE size 32 tại `src/auth.c:142` | `count` cap tại `MAX_ACCOUNTS`; `accounts=256`, không ASan | ASan/UBSan + harness |
| CWE-125 | `src/auth.c:130-146` | record ngắn bị đọc quá heap; ASan `heap-buffer-overflow` READ size 32 tại `src/auth.c:142` | kiểm tra `off > len` / `RECORD_SIZE > len - off`; `accounts=0`, không ASan | ASan/UBSan + harness |

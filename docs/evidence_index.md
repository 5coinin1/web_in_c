# Chỉ mục bằng chứng — 4 chương

> Dùng file này làm “bản đồ” cho Phần 6 (Bằng chứng kiểm chứng) và Phụ lục báo cáo.
> Mọi log đều là file `.txt`/`.json`/`.md` (không dùng `.log` vì `.gitignore` đang bỏ qua `*.log`).

## 0. Tóm tắt số liệu

| Chương | Kết quả chính |
|---|---|
| Ch1 | 185 test PASS; 14 thuộc tính CTL × 4 model; 3 counterexample; `k* = 4` (C) / `5` (Python); 3 model shared |
| Ch2 | 3/3 lỗi ASan trên `-DVULN`; 3/3 case bản vá sạch; cppcheck 0 memory finding (false negative); pattern scanner 3 finding |
| Ch3 | 12/12 SMT+BMC query PASS; 8/8 C harness PASS; witness `L=4096,N=4096 → index=8192` |
| Ch4 | 5/5 pytest PASS; black-box 1500 lần → none; seeded 17 lần → crash; white-box Z3 100.75 ms + 1 lần structural |

## Chương 1 — Kripke + BMC

| Tệp | Nội dung / chứng minh |
|---|---|
| `results/ch1/ch1_kripke_c.txt` | Log runner C: BMC lõi, `k* = 4`, Tier-2 session mutex, Tier-3 room product 216 trạng thái, counterexample |
| `results/ch1/verification.txt` | Log Python 185 test PASS (C replay, 14 thuộc tính × 4 model, shared model) |
| `results/ch1/results.json` | Kết quả từng thuộc tính P1–P7/R1–R5/L1–L2 theo từng model |
| `results/ch1/properties.csv` | Bảng thuộc tính + kết quả model đúng |
| `results/ch1/core_matrix.json` | Bảng chuyển 6 state × 10 event |
| `results/ch1/counterexamples/join_bypass_counterexample.json` | Trace P1/P4 |
| `results/ch1/counterexamples/message_guard_counterexample.json` | Trace P4 |
| `results/ch1/counterexamples/stale_auth_counterexample.json` | Trace P5/P7 |
| `results/ch1/counterexamples/c_counterexample_replay.json` | C buggy nhận JOIN_OK vs C gốc từ chối |
| `python/ch1_kripke/generated/` | Toàn bộ JSON/CSV/DOT gốc (nguồn của `results/ch1/`) |

## Chương 2 — Memory safety

| Tệp | Nội dung / chứng minh |
|---|---|
| `results/ch2/summary.txt` | Bảng tóm tắt 3 bug + 3 case bản vá |
| `results/ch2/results.json` | Dữ liệu có cấu trúc: error/access/size/frame/accounts |
| `results/ch2/asan/vuln_poc_count.dat.txt` | ASan `global-buffer-overflow` WRITE 32 tại `src/auth.c:142` |
| `results/ch2/asan/vuln_poc_short.dat.txt` | ASan `heap-buffer-overflow` READ 32 tại `src/auth.c:142` |
| `results/ch2/asan/vuln_poc_offbyone.dat.txt` | ASan `heap-buffer-overflow` READ 1 tại `src/bytes.h:30` |
| `results/ch2/asan/fixed_poc_*.txt` | Bản vá: không ASan; `accounts=256/0`, `rc=-1` |
| `results/ch2/cppcheck_vuln.xml/.txt` | cppcheck bản `-DVULN` (0 memory finding — false negative) |
| `results/ch2/cppcheck_fixed.xml/.txt` | cppcheck bản vá |
| `results/ch2/pattern_scan.txt/.json` | 3 finding CWE-193/129/125 tại dòng 114/122/142 |
| `results/ch2/pocs/*.dat` | 3 PoC sinh bởi `tools/make_pocs.py` |
| `docs/findings_ch2.md` | Báo cáo Ch2 đủ 5 mục/CWE |

## Chương 3 — SMT/BMC

| Tệp | Nội dung / chứng minh |
|---|---|
| `results/ch3/summary.txt` | Tóm tắt 12/12 query + 8/8 C case |
| `results/ch3/results.json` | 6 SMT + 6 BMC + 8 C case |
| `results/ch3/verification.txt` | Log chạy đầy đủ |
| `results/ch3/smt2/*.smt2` | 12 file SMT-LIB2 tái hiện bằng Z3 |
| `results/ch3/provenance.json` | Z3 version, SHA-256 nguồn, git HEAD |
| `docs/findings_ch3.md` | Báo cáo Ch3 (SMT, BMC, harness, before/after) |

## Chương 4 — Fuzzing

| Tệp | Nội dung / chứng minh |
|---|---|
| `results/ch4/run_fuzzing_demo.txt` | Log 4 kỹ thuật: black-box, guided no-seed, guided seeded, white-box |
| `results/ch4/pytest.txt` | 5/5 test PASS |
| `results/ch4/auth.c.gcov` | Coverage chi tiết `auth.c` |
| `results/ch4/seeds/` | 10 seed corpus dùng cho coverage-guided (rỗng, 4, 6, 12, 100, 188 byte, …) |
| `results/ch4/summary.txt` | Bảng tóm tắt định lượng |
| `docs/findings_ch4.md` | Báo cáo Ch4 + giải thích black-box vs white-box |

## Tổng hợp

| Tệp | Nội dung |
|---|---|
| `docs/cwe_cve_summary.md` | 12 phát hiện, 6 nhóm CWE, ánh xạ CWE/CVE |
| `docs/before_after_all.md` | Bảng before/after tổng hợp 4 chương |
| `docs/findings_ch1.md` … `findings_ch4.md` | Báo cáo từng chương |
| `docs/before_after_ch1.md` … `before_after_ch4.md` | Bảng before/after từng chương |

## Lưu ý

- `results/ch2/build/` và `results/ch3/ch3_harness.exe` là binary, không commit;
  build lại bằng `run_ch2.py` / `ch3_smt/run.py`.
- `python/ch4_fuzzing/_work/` là output tạm của fuzzer (seed, `.gcda/.gcno`,
  binary); có thể dọn trước khi nộp.
- `results/ch1/` được sinh lại bằng:
  `python3 python/ch1_kripke/report.py` (sau khi đã có `generated/`).

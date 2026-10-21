# Tổng hợp CWE/CVE — 4 chương

> Nguồn: `docs/findings_ch1.md` … `docs/findings_ch4.md` và `results/ch1..ch4/`.
> Cột **CVE (ví dụ)** chỉ là ví dụ minh họa lấy từ bảng CWE của môn; đây **không**
> phải CVE của chính project này.

## 1. Bảng tổng hợp

| ID | Chương | Vị trí | Phát hiện | CWE | CVE (ví dụ) | Trạng thái v0 | Trạng thái v1 | Bằng chứng |
|---|---|---|---|---|---|---|---|---|
| CH1-01 | 1 | `src/state_machine.c` — P1 | `join_bypass`: nhận `JOIN_OK` khi chưa login | **CWE-693** (CWE-306) | — | FAIL; trace `FIRST_BYTES → HTTP_UPGRADE_VALID → JOIN_OK` | PASS | `docs/findings_ch1.md`, `results/ch1/counterexamples/join_bypass_counterexample.json` |
| CH1-02 | 1 | `src/state_machine.c` — P4 | `message_guard`: nhận MESSAGE trước khi vào phòng | **CWE-693** (CWE-862) | — | FAIL; trace `FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → MESSAGE_VALID` | PASS | `docs/findings_ch1.md` |
| CH1-03 | 1 | `src/state_machine.c` — P5/P7 | `stale_auth`: giữ `auth_history` sau LOGOUT | **CWE-693** (CWE-613) | — | FAIL; trace `FIRST_BYTES → HTTP_UPGRADE_VALID → LOGIN_OK → LOGOUT` | PASS | `docs/findings_ch1.md` |
| CH1-04 | 1 | `src/session.c` | Hai session cùng active ở biến thể buggy | **CWE-667** | — | counterexample `(A_logged=1, B_logged=1)` | `AG(!(session_A & session_B))` PASS | `results/ch1/ch1_kripke_c.txt` |
| CH1-05 | 1 | `src/room.c` | Xóa phòng lỗi để lại client “stranded” | **CWE-693** (CWE-667) | — | counterexample 4 bước (I1) / 7 bước (I2) | I1/I2/I3 PASS | `results/ch1/ch1_kripke_c.txt` |
| CH2-01 | 2 | `src/auth.c:114` | Header check `len < 11` thay vì `len < 12` | **CWE-193** | — | ASan `heap-buffer-overflow` READ size 1 tại `src/bytes.h:30` | `len < 12`; parser `rc=-1`, không ASan | `results/ch2/asan/vuln_poc_offbyone.dat.txt` |
| CH2-02 | 2 | `src/auth.c:122-147` | `count` từ file không cap `MAX_ACCOUNTS` | **CWE-787** (CWE-129) | — | ASan `global-buffer-overflow` WRITE size 32 tại `src/auth.c:142` | cap 256; `accounts=256`, không ASan | `results/ch2/asan/vuln_poc_count.dat.txt` |
| CH2-03 | 2 | `src/auth.c:130-146` | `off` không kiểm tra với `len` | **CWE-125** (CWE-190) | — | ASan `heap-buffer-overflow` READ size 32 tại `src/auth.c:142` | `accounts=0`, không ASan | `results/ch2/asan/vuln_poc_short.dat.txt` |
| CH3-01 | 3 | `src/read_buffer.h` | NUL terminator ghi tại index 8192 | **CWE-193** | — | SMT SAT `L=4096,N=4096 → index=8192`; harness `bad_index=true` | guard `N ≤ C-1-L`; SMT UNSAT; harness reject | `results/ch3/results.json` |
| CH3-02 | 3 | `src/read_buffer.h` | Nguy cơ tràn signed int32 | **CWE-190** | CVE-2016-5195 (ví dụ) | Có thể xảy ra nếu miền không giới hạn | SMT `signed_overflow=UNSAT` trong miền hợp lệ | `results/ch3/results.json` |
| CH3-03 | 3 | `src/read_buffer.h` | Nếu không chừa byte NUL → ghi quá mảng | **CWE-787** | — | Ghi index 8192 (OOB) | index ≤ 8191 | `results/ch3/results.json` |
| CH4-01 | 4 | `src/auth.c:122` / `src/bytes.h:30` | Fuzzing tìm lại lỗi off-by-one | **CWE-193** (CWE-125/787) | — | crash: seeded 17 lần / white-box 1 lần | fixed build không crash | `results/ch4/run_fuzzing_demo.txt` |

## 2. Thống kê

- **12 mục kiểm chứng/phát hiện** trên 4 chương.
- **6 nhóm CWE**: CWE-693, CWE-667, CWE-193, CWE-787, CWE-125, CWE-190.
- 100% phát hiện v0 đều có bằng chứng v1 tương ứng (bảng before/after).
- Riêng **CH3-02 (CWE-190)** là thuộc tính đã chứng minh **UNSAT** (không tràn
  trong miền hợp lệ), không phải lỗi khai thác được; giữ trong bảng để đối chiếu
  với yêu cầu “tràn số” của Chương 3.
- Không phát hiện deadlock (CWE-833) trên các mô hình Ch1; đây là kết quả
  “không có lỗi” có căn cứ (BMC/CTL).
- CWE-248 (uncaught exception) không áp dụng cho parser C của Ch4; chỉ áp dụng
  nếu bổ sung target Python `divide`/`magic_value` theo spec.

## 3. Ánh xạ theo bảng của môn

| Nguồn phát hiện | CWE chính | Ghi chú |
|---|---|---|
| Vi phạm CTL (Ch1) | CWE-693 | Protection Mechanism Failure |
| Vi phạm loại trừ lẫn nhau / session (Ch1) | CWE-667 | Improper Locking |
| Deadlock (Ch1) | CWE-833 | Không phát hiện trên mô hình |
| Buffer overflow / copy (Ch2, Ch3) | CWE-120 / CWE-787 / CWE-125 | Tùy hướng đọc/ghi |
| Off-by-one (Ch2, Ch3) | CWE-193 | — |
| Tràn số nguyên (Ch3) | CWE-190 | Đã chứng minh UNSAT trong miền hợp lệ |
| Crash khi fuzzing (Ch4) | CWE-193/125/787 | Parser C; CWE-248 nếu target Python |

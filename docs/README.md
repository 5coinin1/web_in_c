# Tài liệu bằng chứng — Chương 1–4

| Tệp | Nội dung |
|---|---|
| `findings_ch1.md` | Báo cáo Ch1: Kripke/CTL, 14 thuộc tính, mutation, product automaton, BMC, counterexample |
| `findings_ch2.md` | Báo cáo Ch2: memory safety, 3 CWE, ASan/UBSan, cppcheck, before/after |
| `findings_ch3.md` | Báo cáo Ch3: SMT/BMC read-buffer append, 6 query + 6 BMC + 8 C case |
| `findings_ch4.md` | Báo cáo Ch4: black-box vs white-box fuzzing, bảng định lượng |
| `before_after_ch1.md` … `before_after_ch4.md` | Bảng before/after từng chương |
| `before_after_all.md` | Bảng before/after tổng hợp 4 chương (mẫu Phần 5) |
| `cwe_cve_summary.md` | 12 phát hiện, 6 nhóm CWE, ánh xạ CWE/CVE |
| `evidence_index.md` | Chỉ mục toàn bộ log/JSON/bằng chứng trong `results/` |

## Thứ tự đọc gợi ý

1. `cwe_cve_summary.md` — nắm toàn bộ phát hiện.
2. `before_after_all.md` — bảng tổng hợp trước/sau.
3. `findings_ch1.md` → `findings_ch4.md` — chi tiết từng chương.
4. `evidence_index.md` — trỏ tới log gốc khi cần trích dẫn.

> Các báo cáo này là **đầu vào** cho báo cáo môn học; còn thiếu bìa, mục lục,
> phần giới thiệu/hạn chế tổng hợp và kết luận (xem `BTL_02` / `report_guide`).

"""Chương 1 — Mô hình hóa & Kiểm chứng hình thức (Kripke + BMC).

Máy trạng thái và Kripke/BMC của dự án đã có sẵn ở C:
    src/state_machine.c, src/kripke.c — chạy bởi test/ch1_kripke.c.
Package này là chỗ đặt phần Python: dựng lại quan hệ chuyển tiếp để đối chiếu,
sinh counterexample, kiểm tra chéo với model C.

TODO (Ch1):
  * kripke.py   : dựng K = (S, S0, R, L) từ state_machine
  * bmc.py      : bounded model checking + completeness threshold
  * liveness.py : EF reachability (safety + liveness)
"""

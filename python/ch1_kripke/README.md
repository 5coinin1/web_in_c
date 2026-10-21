## Cách chạy

```sh
unset MAKE MAKEFLAGS MFLAGS GNUMAKEFLAGS
cmake -S python/ch1_kripke -B python/ch1_kripke/build-websocket -G "MinGW Makefiles" -DCMAKE_C_COMPILER=C:/msys64/mingw64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/mingw64/bin/mingw32-make.exe
cmake --build python/ch1_kripke/build-websocket
ctest --test-dir python/ch1_kripke/build-websocket --verbose --output-on-failure
```

Hoặc mở `run_windows.cmd` (giả định MSYS2 ở C:/msys64).
Script tự chuyển đến thư mục của nó và bỏ các biến Make sai của phiên chạy.
Không sửa biến môi trường toàn máy.

Cần C11 compiler, CMake và Python >=3.9; không cần pip, OpenSSL hoặc Z3.
Nếu CMake không thấy Python, thêm đường dẫn python.exe thật bằng
`-DPython3_EXECUTABLE="C:/.../python.exe"` vào lệnh cấu hình.

Chạy trực tiếp sau khi build:

```sh
python python/ch1_kripke/verify.py --bridge python/ch1_kripke/build-websocket/ch1_chat_bridge.exe
```

Linux: `make -C python/ch1_kripke test`.
MSYS2 có GNU Make cũng dùng được sau bước cấu hình bên trên.
Kết quả hiện tại: **185 tests PASS**, CTest **1/1 PASS** (một runner chứa nhiều kiểm tra).
Bản mới đã chạy Linux. Bản trước từng chạy Windows thành công, nhưng bản mới
vẫn cần chạy lại trên Windows; không coi kết quả cũ là xác nhận bản mới.

##  Cấu trúc

| File | Trách nhiệm |
|---|---|
| kripke.py | Đọc/kiểm tra đồ thị; BFS; AG NOT, AG implication, EF, AG EF |
| model.py | Mô hình lệnh WebSocket ở ranh giới xử lý lệnh |
| products.py | Hai kết nối, session, phòng dùng chung và chẩn đoán LEAVE nhiều bước |
| properties.py | Thuộc tính CTL của mô hình WebSocket |
| bmc.py / liveness.py | Helper bounded checking / khả năng tiến triển |
| c/chat_bridge.c | Xuất state machine C thật, replay lifecycle và mutation bypass riêng trong test |
| handoff.py | Sinh JSON/CSV/DOT, test vectors và code C regression |
| verify.py | Test, đối chiếu C, xuất kết quả và dấu vết nguồn |
| report.py | Sinh `results/ch1/` + `docs/findings_ch1.md` + bảng before/after |
| generated/ | Đầu ra có thể sinh lại, dùng làm bằng chứng/bàn giao |



##  Đọc kết quả

- `generated/verification.txt`: log chạy đầy đủ.
- `generated/results.json`: kết quả từng CTL, witness/counterexample, số test.
- `generated/core_matrix.json`: 6 state × 10 event, kể cả event bị từ chối.
- `generated/none/`: mô hình đúng theo giả định, không phải kết luận toàn bộ server an toàn.
- `generated/join_bypass/`: lỗi vào phòng chưa login.
- `generated/message_guard/`: lỗi chấp nhận MESSAGE trước khi vào phòng.
- `generated/stale_auth/`: lỗi giữ lịch sử xác thực sau logout.
- `generated/*counterexample.json`: phản chứng ngắn nhất từ BFS.
- `generated/c_counterexample_replay.json`: C mutant phát hiện lỗi, C gốc từ chối cùng trace.
- `generated/shared_*.json`: mô hình hai kết nối.
- `generated/leave_window.json`: phân rã LEAVE, chỉ rõ giới hạn giả định atomic command.
- `generated/core_regression.c`: test C sinh tự động từ bảng chuyển đã quan sát.
- `generated/provenance.json`: môi trường và SHA-256 nguồn dùng đối chiếu.

`FAIL` trên mô hình lỗi cố ý là kết quả mong đợi. Runner chỉ PASS khi kỳ vọng
đúng. Có một chẩn đoán thực tế về LEAVE nhiều bước; đọc báo cáo, không bỏ qua.


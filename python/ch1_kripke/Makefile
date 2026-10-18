BUILD ?= build-websocket
.PHONY: all test clean
all:
	cmake -S . -B $(BUILD)
	cmake --build $(BUILD)
test: all
	ctest --test-dir $(BUILD) --verbose --output-on-failure
clean:
	cmake -E remove_directory $(BUILD)

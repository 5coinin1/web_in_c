cmake_minimum_required(VERSION 3.15)
project(wschat C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wno-unused-parameter)

# ---------------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------------
# OpenSSL is located by CMake. If it is not in a standard location, point CMake
# at it when configuring (do NOT hardcode paths here), e.g.:
#     cmake -DOPENSSL_ROOT_DIR=C:/msys64/mingw64 -B build
# or use the provided CMakePresets.json ("windows-mingw").
find_package(OpenSSL REQUIRED)

# POSIX threads (winpthread on MinGW)
find_package(Threads REQUIRED)

# Windows socket library
if(WIN32)
    set(WS_LIBS ws2_32)
else()
    set(WS_LIBS "")
endif()

set(SERVER_SOURCES
    src/main.c
    src/client.c
    src/ws_frame.c
    src/http_upgrade.c
    src/room.c
    src/auth.c
    src/session.c
    src/json_util.c
    src/log.c
    src/tui.c
    src/state_machine.c
)

# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
add_executable(wschat_server ${SERVER_SOURCES})
target_include_directories(wschat_server PRIVATE src)
target_link_libraries(wschat_server PRIVATE
    Threads::Threads
    ${WS_LIBS}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# ---------------------------------------------------------------------------
# Test client
# ---------------------------------------------------------------------------
add_executable(wschat_client
    src/client_main.c
    src/ws_frame.c
    src/json_util.c
    src/log.c
    src/tui.c
)
target_include_directories(wschat_client PRIVATE src)
target_link_libraries(wschat_client PRIVATE
    Threads::Threads
    ${WS_LIBS}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# ---------------------------------------------------------------------------
# Vulnerable build + fuzzing harness (see README: "Injected vulnerabilities").
#
# wschat_server_vuln and wschat_fuzz_store compile the parser with -DVULN,
# which enables the intentionally injected bugs. The plain wschat_server is
# the fixed build. Enable WCHAT_SANITIZE to add ASan/UBSan to these targets.
# ---------------------------------------------------------------------------
add_executable(wschat_server_vuln ${SERVER_SOURCES})
target_include_directories(wschat_server_vuln PRIVATE src)
target_compile_definitions(wschat_server_vuln PRIVATE VULN)
if(WCHAT_SANITIZE)
    target_compile_options(wschat_server_vuln PRIVATE -fsanitize=address,undefined -g -O1)
    target_link_options(wschat_server_vuln PRIVATE -fsanitize=address,undefined)
endif()
target_link_libraries(wschat_server_vuln PRIVATE
    Threads::Threads
    ${WS_LIBS}
    OpenSSL::SSL
    OpenSSL::Crypto
)

add_executable(wschat_fuzz_store_vuln test/fuzz_store.c src/auth.c src/log.c)
target_include_directories(wschat_fuzz_store_vuln PRIVATE src)
target_compile_definitions(wschat_fuzz_store_vuln PRIVATE VULN)
if(WCHAT_SANITIZE)
    target_compile_options(wschat_fuzz_store_vuln PRIVATE -fsanitize=address,undefined -g -O1)
    target_link_options(wschat_fuzz_store_vuln PRIVATE -fsanitize=address,undefined)
endif()
target_link_libraries(wschat_fuzz_store_vuln PRIVATE
    Threads::Threads
    ${WS_LIBS}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Clean (fixed) parser harness - for before/after comparison.
add_executable(wschat_fuzz_store test/fuzz_store.c src/auth.c src/log.c)
target_include_directories(wschat_fuzz_store PRIVATE src)
if(WCHAT_SANITIZE)
    target_compile_options(wschat_fuzz_store PRIVATE -fsanitize=address,undefined -g -O1)
    target_link_options(wschat_fuzz_store PRIVATE -fsanitize=address,undefined)
endif()
target_link_libraries(wschat_fuzz_store PRIVATE
    Threads::Threads
    ${WS_LIBS}
    OpenSSL::SSL
    OpenSSL::Crypto
)

# ---------------------------------------------------------------------------
# Optional sanitizer build (ASan/UBSan). Requires a toolchain that ships the
# sanitizer runtimes (GCC/Clang on Linux/macOS). Not available with MinGW.
# Enable with: -DWCHAT_SANITIZE=ON
# ---------------------------------------------------------------------------
option(WCHAT_SANITIZE "Build the server with AddressSanitizer/UBSan" OFF)

if(WCHAT_SANITIZE)
    add_executable(wschat_server_asan ${SERVER_SOURCES})
    target_include_directories(wschat_server_asan PRIVATE src)
    target_compile_options(wschat_server_asan PRIVATE -fsanitize=address,undefined -g -O1)
    target_link_options(wschat_server_asan PRIVATE -fsanitize=address,undefined)
    target_link_libraries(wschat_server_asan PRIVATE
        Threads::Threads
        ${WS_LIBS}
        OpenSSL::SSL
        OpenSSL::Crypto
    )
endif()
# ---------------------------------------------------------------------------
# Chapter 1 - Shared State Machine + Kripke / BMC
# ---------------------------------------------------------------------------

add_executable(wschat_ch1_kripke
    test/ch1_kripke.c
    src/state_machine.c
    src/kripke.c
)

target_include_directories(
    wschat_ch1_kripke
    PRIVATE
    src
)

enable_testing()

add_test(
    NAME chapter1_kripke
    COMMAND wschat_ch1_kripke 8
)
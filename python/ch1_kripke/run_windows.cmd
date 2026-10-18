@echo off
setlocal
cd /d "%~dp0"
set "PATH=C:\msys64\mingw64\bin;%PATH%"
set "MAKE="
set "MAKEFLAGS="
set "MFLAGS="
set "GNUMAKEFLAGS="
cmake -S . -B build-websocket -G "MinGW Makefiles" -DCMAKE_C_COMPILER=C:/msys64/mingw64/bin/gcc.exe -DCMAKE_MAKE_PROGRAM=C:/msys64/mingw64/bin/mingw32-make.exe
if errorlevel 1 goto failed
cmake --build build-websocket
if errorlevel 1 goto failed
ctest --test-dir build-websocket --verbose --output-on-failure
if errorlevel 1 goto failed
echo.
echo PASS - Read generated\verification.txt and README.md.
pause
exit /b 0
:failed
echo.
echo FAILED - Copy the error above for diagnosis.
pause
exit /b 1

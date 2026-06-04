@echo off
echo Compiling custom C NTT Backend for Windows...
gcc -O3 -shared -o ntt.dll ntt.c
if %errorlevel% neq 0 (
    echo [ERROR] Compilation failed!
    exit /b %errorlevel%
)
echo [SUCCESS] ntt.dll compiled successfully!

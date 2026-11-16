@echo off
setlocal
cd /d "%~dp0"

where nasm >nul 2>nul
if errorlevel 1 (
    echo [错误] 未找到 nasm。请先安装 NASM：https://www.nasm.us/ 或 winget install nasm
    exit /b 1
)

echo [*] 编译 x64 加载桩...
nasm -f bin -o loader_x64.bin loader_x64.asm
if errorlevel 1 (
    echo [错误] x64 编译失败
    exit /b 1
)

echo [*] 编译 x86 加载桩...
nasm -f bin -o loader_x86.bin loader_x86.asm
if errorlevel 1 (
    echo [错误] x86 编译失败
    exit /b 1
)

echo [*] 完成：loader_x64.bin / loader_x86.bin
exit /b 0

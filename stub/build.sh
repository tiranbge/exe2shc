#!/usr/bin/env sh
set -e
cd "$(dirname "$0")"

if ! command -v nasm >/dev/null 2>&1; then
    echo "[错误] 未找到 nasm。请先安装 NASM（apt install nasm / brew install nasm）"
    exit 1
fi

echo "[*] 编译 x64 加载桩..."
nasm -f bin -o loader_x64.bin loader_x64.asm

echo "[*] 编译 x86 加载桩..."
nasm -f bin -o loader_x86.bin loader_x86.asm

echo "[*] 完成：loader_x64.bin / loader_x86.bin"

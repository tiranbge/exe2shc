#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
从 CLR2SC 的 index.html 中提取 bootstrap shellcode 并解码为二进制文件。

CLR2SC (https://github.com/Laster-dev/CLR2SC) 的 bootstrap 是 base64 编码的
原生引导桩，负责在内存中启动 CLR 并 Assembly.Load 内嵌的 .NET 程序集。

每个 bootstrap 含两个 "AAAA"(0x41414141) 占位符：
  第 1 个 = 保存程序集长度（mov [reg], len）
  第 2 个 = memcpy 长度（mov ecx/rcx, len）
生成时把两个占位符都替换为程序集字节数（小端 uint32），
再把程序集字节拼在 bootstrap 之后（bootstrap 需去掉最后一个字节）。
"""
import base64
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
# 脚本与 HTML 同位于 stub/clr/ 下
HTML = os.path.join(HERE, "clr2sc_index.html")

# CLR2SC 键名 -> 目标文件名
VARIANTS = {
    "sc-32-clr":          "clr_x86.bin",
    "sc-64-clr":          "clr_x64.bin",
    "sc-32-clr-apc":      "clr_x86_apc.bin",
    "sc-64-clr-apc":      "clr_x64_apc.bin",   # CLR2SC 未提供，仅为占位
    "sc-32-clrnd":        "clr_x86_newdomain.bin",
    "sc-64-clrnd":        "clr_x64_newdomain.bin",
    "sc-32-clrnd-apc":    "clr_x86_newdomain_apc.bin",
    "sc-64-clrnd-apc":    "clr_x64_newdomain_apc.bin",  # CLR2SC 未提供，仅为占位
}

PLACEHOLDER = b"\x41\x41\x41\x41"


def find_all_placeholders(blob):
    positions = []
    start = 0
    while True:
        i = blob.find(PLACEHOLDER, start)
        if i == -1:
            break
        positions.append(i)
        start = i + 1
    return positions


def main():
    with open(HTML, "r", encoding="utf-8") as f:
        html = f.read()

    os.makedirs(HERE, exist_ok=True)

    for key, fname in VARIANTS.items():
        m = re.search(r"'%s'\s*:\s*'([^']+)'" % re.escape(key), html)
        if not m:
            print("[跳过] 未找到 %s" % key)
            continue
        blob = base64.b64decode(m.group(1))
        pos = find_all_placeholders(blob)
        out = os.path.join(HERE, fname)
        with open(out, "wb") as f:
            f.write(blob)
        print("[+] %-24s -> %-30s %5d bytes  占位符=%s"
              % (key, fname, len(blob), pos))


if __name__ == "__main__":
    main()

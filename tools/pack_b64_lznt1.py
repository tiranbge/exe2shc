#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pack_b64_lznt1.py —— 给 stub/dec_b64_lznt1.asm 生产载荷

产物布局：
    [stub 代码][可选实例参数块][数据块 0x14 字节头 + Z85 文本]
数据块头：
    +0x00 u32 enclen    Z85 文本长度
    +0x04 u32 complen   Z85 解码后长度（= LZNT1 压缩后长度）
    +0x08 u32 rawlen    解压后长度（--container 时 = 容器长度）
    +0x0C u64 fnv64     解压后内容的 FNV-1a 64（--test 版校验用）

两种模式：
  1) 容器模式（默认）：解压出来是「容器」（PE 精简中间表示），由 RUN_CONTAINER 版的 stub
     自己重建镜像 + 重定位 + 修 IAT + 跳入口，不需要 loader。节数据默认不加密。
  2) 裸 PE 模式（--no-container，或显式给了 --asm）：解压出来直接是原始 PE/字节，
     交给 loader_x64.asm 的标准 PE 流程

用法：
    # 默认：容器模式（Z85 + LZNT1），产物直接可跑
    python pack_b64_lznt1.py --payload in.exe --out run.bin
    .\runshc64.exe run.bin

    # 自校验（退出码 0 = asm 解码与源数据逐字节一致）
    python pack_b64_lznt1.py --payload in.exe --out t.bin --test

    # 关掉容器层，交给 loader
    python pack_b64_lznt1.py --payload in.exe --out run.bin --no-container
    # 需要混淆时才给节数据加 XOR
    python pack_b64_lznt1.py --payload in.exe --out run.bin --key-len 11
"""

import argparse
import ctypes
import ctypes.wintypes
import os
import random
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
DEFAULT_ASM = os.path.join(REPO, "stub", "dec_b64_lznt1.asm")
DEFAULT_ASM_X86 = os.path.join(REPO, "stub", "dec_b64_lznt1_x86.asm")
NASM = os.path.join(REPO, "tools", "nasm-2.16.03", "nasm.exe")


def find_nasm() -> str:
    """优先用仓库自带/安装的 nasm，其次退到 PATH 里的 nasm。"""
    if os.path.isfile(NASM):
        return NASM
    for name in ("nasm", "nasm.exe"):
        found = shutil.which(name)
        if found:
            return found
    sys.exit("[!] 找不到 nasm：%s 不存在，PATH 里也没有 nasm" % NASM)


EMPTY_ARGS = bytes(4)   # 空实例参数块：cmdlineLen=0, imagePathLen=0
FNV_OFFSET = 0xCBF29CE484222325
FNV_PRIME = 0x100000001B3


# ---------------------------------------------------------------- LZNT1 ----
def lznt1_compress(data: bytes) -> bytes:
    """用 ntdll!RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1) 压缩。"""
    ntdll = ctypes.WinDLL("ntdll")

    ws = ctypes.wintypes.ULONG()
    frag = ctypes.wintypes.ULONG()
    ntdll.RtlGetCompressionWorkSpaceSize(2, ctypes.byref(ws), ctypes.byref(frag))
    work = ctypes.create_string_buffer(ws.value)

    cap = len(data) + len(data) // 8 + 0x2000
    dst = ctypes.create_string_buffer(cap)
    final = ctypes.wintypes.ULONG()
    st = ntdll.RtlCompressBuffer(
        2, data, len(data), dst, cap, 4096, ctypes.byref(final), work
    )
    if st != 0:
        raise RuntimeError("RtlCompressBuffer failed NTSTATUS=0x%08X" % (st & 0xFFFFFFFF))
    return dst.raw[: final.value]


def lznt1_decompress(data: bytes, rawlen: int) -> bytes:
    ntdll = ctypes.WinDLL("ntdll")
    dst = ctypes.create_string_buffer(rawlen + 0x1000)
    final = ctypes.wintypes.ULONG()
    st = ntdll.RtlDecompressBuffer(
        2, dst, rawlen + 0x1000, data, len(data), ctypes.byref(final)
    )
    if st != 0:
        raise RuntimeError("RtlDecompressBuffer failed NTSTATUS=0x%08X" % (st & 0xFFFFFFFF))
    return dst.raw[: final.value]


def fnv64(data: bytes) -> int:
    h = FNV_OFFSET
    for b in data:
        h = ((h ^ b) * FNV_PRIME) & 0xFFFFFFFFFFFFFFFF
    return h


# ------------------------------------------------------------- 容器层 ------
def parse_pe(data: bytes):
    """最小 PE32+ 解析，拿到容器层需要的字段。"""
    if data[:2] != b"MZ":
        sys.exit("[!] 不是 MZ 文件")
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e : e + 4] != b"PE\0\0":
        sys.exit("[!] 没有 PE 签名")
    nsect = struct.unpack_from("<H", data, e + 6)[0]
    optsize = struct.unpack_from("<H", data, e + 20)[0]
    opt = e + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic != 0x20B:
        sys.exit("[!] 只支持 PE32+ (x64)，本文件 OptionalHeader magic=0x%X" % magic)

    entry = struct.unpack_from("<I", data, opt + 16)[0]
    image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
    ndirs = struct.unpack_from("<I", data, opt + 108)[0]
    dirs = opt + 112

    def dd(i):
        if i >= ndirs:
            return 0, 0
        return struct.unpack_from("<II", data, dirs + i * 8)

    imp_rva, _imp_sz = dd(1)
    rel_rva, rel_sz = dd(5)
    tls_rva, tls_sz = dd(9)
    pdata_rva, pdata_sz = dd(3)

    secoff = opt + optsize
    sects = []
    for i in range(nsect):
        o = secoff + i * 40
        name = data[o : o + 8].rstrip(b"\0").decode("latin-1")
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, o + 8)
        sects.append((name, vaddr, vsize, rawsize, rawptr))

    return dict(
        entry=entry,
        image_base=image_base,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        imp_rva=imp_rva,
        rel_rva=rel_rva,
        rel_sz=rel_sz,
        tls_rva=tls_rva,
        tls_sz=tls_sz,
        pdata_rva=pdata_rva,
        pdata_sz=pdata_sz,
        sects=sects,
    )


# 需要「路径/MUI/消息表」兼容层的导入名：命中任意一个就编进兼容层
COMPAT_IMPORTS = {
    "GetModuleFileNameW",
    "LoadStringW",
    "FormatMessageW",
    "FindResourceW",
    "FindResourceExW",
    "LoadResource",
    "SizeofResource",
}


def _rva_to_off(rva: int, sects) -> int:
    for _name, vaddr, vsize, rawsize, rawptr in sects:
        if vaddr <= rva < vaddr + max(vsize, rawsize):
            return rva - vaddr + rawptr
    return -1


def imported_names(pe: bytes, info=None) -> set:
    """扫导入表，返回所有被导入的函数名（按名导入的）。"""
    if info is None:
        info = parse_pe(pe)
    out = set()
    off = _rva_to_off(info["imp_rva"], info["sects"])
    if off < 0:
        return out
    while True:
        try:
            oft, _ts, _fc, name_rva, ft = struct.unpack_from("<IIIII", pe, off)
        except struct.error:
            break
        if name_rva == 0:
            break
        thunk = _rva_to_off(oft or ft, info["sects"])
        if thunk < 0:
            break
        k = 0
        while True:
            try:
                ent = struct.unpack_from("<Q", pe, thunk + 8 * k)[0]
            except struct.error:
                break
            if ent == 0:
                break
            if ent >> 63 == 0:
                n_off = _rva_to_off(ent & 0x7FFFFFFF, info["sects"])
                if n_off < 0:
                    break
                out.add(pe[n_off + 2 :].split(chr(0).encode())[0].decode("latin-1"))
            k += 1
            if k > 4096:
                break
        off += 20
        if off > len(pe) or off - info["sects"][0][4] > 0x100000:
            break
    return out



def imported_modules(pe: bytes, info=None) -> list:
    """导入表里的模块名列表（用于判断是否 mingw/ucrt CRT）。"""
    if info is None:
        info = parse_pe(pe)
    out = []
    off = _rva_to_off(info["imp_rva"], info["sects"])
    if off < 0:
        return out
    while True:
        try:
            _oft, _ts, _fc, name_rva, _ft = struct.unpack_from("<IIIII", pe, off)
        except struct.error:
            break
        if name_rva == 0:
            break
        n_off = _rva_to_off(name_rva, info["sects"])
        if n_off < 0:
            break
        out.append(pe[n_off:].split(chr(0).encode())[0].decode("latin-1"))
        off += 20
    return out


def needs_compat(pe: bytes, info=None) -> bool:
    """这个 exe 是否真的需要路径/MUI/消息表那套兜底。"""
    return bool(imported_names(pe, info) & COMPAT_IMPORTS)


def build_container(pe: bytes, key_len: int = 0, cmdline: str = "", modpath: str = "") -> bytes:
    """PE 文件 -> 容器（头 + 密钥 + 节表 + 可选命令行 + 紧排节数据）。

    命令行块位于节表之后、节数据之前：u32 len + UTF-16LE 字节；
    长度 0 时 stub 用内置的 "X.exe"。
    """
    info = parse_pe(pe)
    sects = info["sects"]
    nsect = len(sects)

    # +0x1C TLSRVA / +0x20 TLSSize / +0x24 PdataRVA / +0x28 PdataSize
    # +0x2C HdrSize / +0x30 HdrOff / +0x34 NSect / +0x38 KeyLen / +0x3C Key[KeyLen]
    # 节表 / CmdLen+cmd / PE 头 blob / 节数据
    hdr_size = min(info.get("size_of_headers", 0x400) or 0x400, 0x1000)
    hdr_blob = pe[:hdr_size]
    key = bytes(random.randrange(256) for _ in range(key_len))
    cmd = cmdline.encode("utf-16-le") if cmdline else b""
    cmd_blob = struct.pack("<I", len(cmd)) + cmd
    # 末尾补 NUL：stub 里直接把它当 C 宽串传给 LoadLibraryExW
    mod = (modpath.encode("utf-16-le") + chr(0).encode("utf-16-le")) if modpath else b""
    mod_blob = struct.pack("<I", len(mod)) + mod

    # 打包时算好的 MUI 候选路径（运行时不拼字符串）
    mui = b""
    if modpath:
        _d, _b = os.path.split(modpath)
        for _lang in ("zh-CN", "en-US"):
            _cand = os.path.join(_d, _lang, _b + ".mui")
            _w = _cand.encode("utf-16-le") + b"\x00\x00"
            mui += struct.pack("<I", len(_w)) + _w
    mui_blob = struct.pack("<I", len(mui)) + mui


    table_start = 0x3C + key_len
    hdr_off = (table_start + 12 * nsect + len(cmd_blob) + len(mod_blob)
               + len(mui_blob))
    body_start = hdr_off + len(hdr_blob)

    hdr = struct.pack(
        "<IIQIIIIIIIIIII",
        info["size_of_image"],
        info["entry"],
        info["image_base"],
        info["imp_rva"],
        info["rel_rva"],
        info["rel_sz"],
        info.get("tls_rva", 0),
        info.get("tls_sz", 0),
        info.get("pdata_rva", 0),
        info.get("pdata_sz", 0),
        len(hdr_blob),
        hdr_off,
        nsect,
        key_len,
    )
    assert len(hdr) == 0x3C, len(hdr)

    table = bytearray()
    body = bytearray()
    off = body_start
    for _name, vaddr, vsize, rawsize, rawptr in sects:
        n = rawsize
        if vsize and n > vsize:          # 与 Windows 加载器一致：不超过 VirtualSize
            n = vsize
        if rawptr > len(pe):
            n = 0
        elif rawptr + n > len(pe):
            n = len(pe) - rawptr
        chunk = bytearray(pe[rawptr : rawptr + n])
        if key_len:
            for i in range(len(chunk)):
                chunk[i] ^= key[i % key_len]
        table += struct.pack("<III", vaddr, off, len(chunk))
        body += chunk
        off += len(chunk)

    return (bytes(hdr) + key + bytes(table) + cmd_blob + mod_blob + mui_blob
            + hdr_blob + bytes(body))


# --------------------------------------------------------------- 打包 ------
# ---------------------------------------------------------------- Z85 (ZeroMQ base85)
Z85_ALPHA = (b"0123456789abcdefghijklmnopqrstuvwxyz"
             b"ABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")
assert len(Z85_ALPHA) == 85
Z85_TAB = [255] * 95          # 索引 = ch - 33，覆盖 33..127


def _z85_build_tab():
    for i, ch in enumerate(Z85_ALPHA):
        Z85_TAB[ch - 33] = i


_z85_build_tab()


def z85_encode(data: bytes) -> bytes:
    """4 字节 -> 5 字符，长度不足补 0（解码端按 complen 截断）。"""
    pad = (-len(data)) % 4
    buf = data + bytes(pad)
    out = bytearray()
    for i in range(0, len(buf), 4):
        v = int.from_bytes(buf[i : i + 4], "big")
        chunk = bytearray(5)
        for k in range(4, -1, -1):
            chunk[k] = Z85_ALPHA[v % 85]
            v //= 85
        out += chunk
    return bytes(out)


def z85_decode(text: bytes, out_len: int = 0) -> bytes:
    out = bytearray()
    for i in range(0, len(text), 5):
        v = 0
        for ch in text[i : i + 5]:
            idx = ch - 33
            if idx < 0 or idx >= 95 or Z85_TAB[idx] == 255:
                raise ValueError("bad z85 char %r" % ch)
            v = v * 85 + Z85_TAB[idx]
        out += v.to_bytes(4, "big")
    return bytes(out[:out_len]) if out_len else bytes(out)


def build_instance_block(cmdline: str, image_path: str) -> bytes:
    """实例参数块：u16 cmdlineLen, u16 imagePathLen, 串..."""
    cmd = cmdline.encode("utf-16-le") if cmdline else b""
    img = image_path.encode("utf-16-le") if image_path else b""
    return struct.pack("<HH", len(cmd), len(img)) + cmd + b"\x00\x00" + img + b"\x00\x00"


def build(stub: bytes, payload: bytes, with_fnv: bool = True,
          empty_args: bool = False, inst: bytes = b"") -> bytes:
    comp = lznt1_compress(payload)
    b64 = z85_encode(comp)
    hdr = struct.pack(
        "<IIIQ",
        len(b64),
        len(comp),
        len(payload),
        fnv64(payload) if with_fnv else 0,
    )
    if inst:
        pass
    elif empty_args:
        inst = EMPTY_ARGS
    return stub + inst + hdr + b64


def assemble_x86(extra: list = None) -> bytes:
    """汇编 32 位 Z85+LZNT1 自解压桩。"""
    return assemble(DEFAULT_ASM_X86, False, extra or [])


def wrap(inner: bytes, arch: str = "x64", extra: list = None) -> bytes:
    """用对应架构的自解压桩包住任意载荷（解压后直接 call）。"""
    stub = assemble_x86(extra) if arch in ("x86", "x32", "i386") else assemble(
        DEFAULT_ASM, False, extra or ["RUN_RAW"])
    return build(stub, inner, with_fnv=False)


def verify(blob: bytes, stub_len: int, payload: bytes, inst_len: int = 0) -> None:
    """按 stub 的逻辑（z85 -> LZNT1）解一遍，和目标字节比。"""
    head = stub_len + inst_len
    b64len, complen, rawlen, expect = struct.unpack("<IIIQ", blob[head : head + 0x14])
    text = blob[head + 0x14 : head + 0x14 + b64len]
    assert len(text) == b64len, "b64len 不符"
    decoded = z85_decode(text, complen)
    assert len(decoded) == complen, "complen 不符：%d != %d" % (len(decoded), complen)
    raw = lznt1_decompress(decoded, rawlen)
    assert len(raw) == rawlen, "rawlen 不符"
    assert raw == payload, "解压内容与目标字节不一致"
    assert expect == 0 or expect == fnv64(payload), "fnv64 不符"


def assemble(asm_path: str, test: bool, extra: list = None) -> bytes:
    nasm = find_nasm()
    build_dir = os.path.join(REPO, "build")
    os.makedirs(build_dir, exist_ok=True)
    # nasm 处理中文/绝对路径不稳，全部用相对 REPO 的路径并从 REPO 启动
    tmp_rel = os.path.join("build", "_stub_tmp.bin")
    asm_rel = os.path.relpath(asm_path, REPO)
    inc = os.path.dirname(asm_rel) or "."
    cmd = [nasm, "-f", "bin", "-I", inc + os.sep, "-I", "stub" + os.sep, "-o", tmp_rel]
    if test:
        cmd.append("-DTEST_HARNESS")
    for d in extra or []:
        cmd.append("-D" + d)
    cmd.append(asm_rel)
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO)
    if r.returncode != 0:
        sys.exit("[!] nasm 失败：\n%s%s" % (r.stdout, r.stderr))
    with open(os.path.join(REPO, tmp_rel), "rb") as f:
        stub = f.read()
    os.remove(os.path.join(REPO, tmp_rel))
    return stub


def main() -> None:
    try:
        sys.stdout.reconfigure(errors="replace")
    except Exception:
        pass
    ap = argparse.ArgumentParser()
    ap.add_argument("--payload", required=True, help="原始载荷（PE 或任意字节）")
    ap.add_argument("--out", required=True, help="输出 .bin")
    ap.add_argument("--asm", default=None, help="解码段 asm（默认 stub/dec_b64_lznt1.asm）")
    ap.add_argument("--test", action="store_true", help="-DTEST_HARNESS：自校验并 ExitProcess")
    ap.add_argument("--no-fnv", action="store_true", help="数据块 +0x0C 填 0")
    ap.add_argument("--cmdline", default="", help="实例参数块里的 CommandLine")
    ap.add_argument("--image-path", default="", help="实例参数块里的 ImagePathName")
    ap.add_argument("--empty-args", action="store_true",
                    help="stub 后先插 4 字节空实例参数块（拼进 loader 的 demo 用）")
    ap.add_argument("--container", dest="container", action="store_true", default=None,
                    help="容器模式（默认开启）：PE 拆成容器，用 -DRUN_CONTAINER 的 stub 自跑")
    ap.add_argument("--no-container", dest="container", action="store_false",
                    help="关闭容器层：解压出来是原始 PE，交给 loader_x64.asm")
    ap.add_argument("--key-len", type=int, default=0,
                    help="容器内节数据的 XOR 密钥长度（默认 0 = 不加密）")
    args = ap.parse_args()

    with open(args.payload, "rb") as f:
        raw = f.read()

    # 默认容器模式；显式给了 --asm（例如 loader 副本）则视为裸 PE 模式
    if args.container is None:
        args.container = args.asm is None

    if args.container:
        data = build_container(raw, args.key_len)
        asm = args.asm or DEFAULT_ASM
        stub = assemble(asm, args.test, ["RUN_CONTAINER"])
    else:
        data = raw
        asm = args.asm or DEFAULT_ASM
        stub = assemble(asm, args.test)

    inst = b""
    if args.cmdline or args.image_path:
        inst = build_instance_block(args.cmdline, args.image_path)

    blob = build(stub, data, with_fnv=not args.no_fnv, empty_args=args.empty_args, inst=inst)
    verify(blob, len(stub), data, len(inst) if inst else (4 if args.empty_args else 0))

    with open(args.out, "wb") as f:
        f.write(blob)

    comp_len = len(lznt1_compress(data))
    print("[+] payload  : %s (%d 字节)" % (args.payload, len(raw)))
    if args.container:
        print("[+] 容器     : %d 字节（%d 节, XOR 密钥 %d 字节）"
              % (len(data), len(parse_pe(raw)["sects"]), args.key_len))
    print("[+] stub     : %d 字节%s%s" % (len(stub),
                                          "  [TEST]" if args.test else "",
                                          "  [CONTAINER]" if args.container else ""))
    print("[+] 压缩后   : %d 字节（z85 前）" % comp_len)
    print("[+] 输出     : %s (%d 字节)" % (args.out, len(blob)))
    print("[+] verify   : z85 + LZNT1 roundtrip OK")


if __name__ == "__main__":
    main()

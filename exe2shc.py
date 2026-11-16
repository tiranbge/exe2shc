#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
exe2shellcode — 将 Windows PE (EXE) 转换为可在内存中执行的 shellcode。

特性：
  * 自动识别 x86 / x64 架构并选用对应加载桩
  * 支持运行时向目标程序传递命令行参数（写入 PEB->ProcessParameters->CommandLine）
  * 纯标准库实现，无第三方运行依赖

产物布局：
  +---------------+----------------+---------------+
  | loader stub   |  args block    |  原始 EXE 字节 |
  +---------------+----------------+---------------+
"""

import argparse
import os
import shutil
import struct
import subprocess
import sys
import tempfile

MACHINE_X64 = 0x8664
MACHINE_X86 = 0x014C

ARCH_NAMES = {
    MACHINE_X64: "x64",
    MACHINE_X86: "x86",
}

# CLR bootstrap（.NET 托管程序集适配，参考 https://github.com/Laster-dev/CLR2SC）
# 引导桩负责在内存中启动 CLR 运行时，并用 Assembly.Load 加载内嵌程序集。
# 每个引导桩含两个 "AAAA" 占位符，分别对应「保存程序集长度」与「memcpy 长度」。
CLR_PLACEHOLDER = b"\x41\x41\x41\x41"  # "AAAA"

# 加载桩目录：默认为脚本所在目录下的 stub（绝对路径，避免受工作目录影响）
DEFAULT_STUB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "stub")


class PEInfo:
    """解析出的 PE 关键信息。"""

    def __init__(self, machine, entry_rva, image_base, size_of_image,
                 size_of_headers, size_of_optional_header, subsystem,
                 number_of_sections, section_table_offset):
        self.machine = machine
        self.entry_rva = entry_rva
        self.image_base = image_base
        self.size_of_image = size_of_image
        self.size_of_headers = size_of_headers
        self.size_of_optional_header = size_of_optional_header
        self.subsystem = subsystem
        self.number_of_sections = number_of_sections
        self.section_table_offset = section_table_offset

    @property
    def arch(self):
        return ARCH_NAMES.get(self.machine)

    @property
    def is64(self):
        return self.machine == MACHINE_X64


def parse_pe(data):
    """解析 PE 文件，返回 PEInfo。失败抛 ValueError。"""
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise ValueError("不是有效的 PE 文件（缺少 MZ 头）")

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("不是有效的 PE 文件（PE 签名缺失）")

    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    number_of_sections = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    size_of_optional_header = struct.unpack_from("<H", data, e_lfanew + 20)[0]

    opt = e_lfanew + 24
    if opt + 2 > len(data):
        raise ValueError("PE 可选头越界")

    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:  # PE32+
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    elif magic == 0x10B:  # PE32
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
        size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    else:
        raise ValueError("无法识别的可选头 Magic: 0x%04X" % magic)

    if machine not in ARCH_NAMES:
        raise ValueError(
            "不支持的架构 Machine=0x%04X（仅支持 x86 0x014C / x64 0x8664）" % machine)

    section_table_offset = opt + size_of_optional_header

    return PEInfo(
        machine=machine,
        entry_rva=entry_rva,
        image_base=image_base,
        size_of_image=size_of_image,
        size_of_headers=size_of_headers,
        size_of_optional_header=size_of_optional_header,
        subsystem=subsystem,
        number_of_sections=number_of_sections,
        section_table_offset=section_table_offset,
    )


def build_instance_block(cmdline, image_path):
    """
    构造实例参数块（Donut 风格，小端）：

        +0x00: uint16  cmdlineLen    —— CommandLine 的 UTF-16LE 字节数（不含结尾 null）
        +0x02: uint16  imagePathLen  —— ImagePathName 的 UTF-16LE 字节数（不含结尾 null）
        +0x04: CommandLine  UTF-16LE 字符串，以 \\x00\\x00 结尾
        +... : ImagePathName UTF-16LE 字符串，以 \\x00\\x00 结尾

    嵌入 EXE 起始地址 = 4 + cmdlineLen + 2 + imagePathLen + 2
    """
    cmd = cmdline.encode("utf-16-le") if cmdline else b""
    img = image_path.encode("utf-16-le") if image_path else b""
    header = struct.pack("<HH", len(cmd), len(img))
    return header + cmd + b"\x00\x00" + img + b"\x00\x00"


def load_stub(stub_dir, arch):
    """读取对应架构的加载桩。"""
    fname = "loader_x64.bin" if arch == "x64" else "loader_x86.bin"
    path = os.path.join(stub_dir, fname)
    if not os.path.isfile(path):
        raise FileNotFoundError(
            "找不到加载桩 %s。请先在 stub/ 目录运行 build.bat（或 build.sh）用 nasm 编译。"
            % path)
    with open(path, "rb") as f:
        return f.read()


def dotnet_arch(data):
    """
    .NET 程序集实际该按哪个位宽跑。

    PE machine=0x014C 只表示 IL-only（AnyCPU），不代表必须 32 位：
    64 位系统上 AnyCPU 会以 x64 运行。只有 COR20 头里
    COMIMAGE_FLAGS_32BITREQUIRED(0x02) 或 32BITPREFERRED(0x20000000)
    才是真的 32 位。
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return "x64"
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    if machine == 0x8664:
        return "x64"
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic not in (0x10B, 0x20B):
        return "x64"
    optsz = struct.unpack_from("<H", data, e_lfanew + 20)[0]
    dd = opt + (112 if magic == 0x20B else 96)
    cli_rva = struct.unpack_from("<I", data, dd + 14 * 8)[0]
    if cli_rva == 0:
        return "x64"
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    so = opt + optsz
    for i in range(nsec):
        b = so + i * 40
        vsize, va, rawsz, rawptr = struct.unpack_from("<IIII", data, b + 8)
        if va <= cli_rva < va + max(vsize, rawsz):
            off = cli_rva - va + rawptr
            if off + 20 <= len(data):
                flags = struct.unpack_from("<I", data, off + 16)[0]
                if flags & 0x2 or flags & 0x20000000:
                    return "x86"
            break
    return "x64"


def is_dotnet(data):
    """
    判断 PE 是否为 .NET 托管程序集。

    依据：DataDirectory[14]（IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR，CLR 头）
    的 RVA 非零。原生 PE 该目录为空。
    """
    if len(data) < 0x40 or data[:2] != b"MZ":
        return False
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 + 2 > len(data):
        return False
    opt = e_lfanew + 24
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:      # PE32+
        dd = opt + 112
    elif magic == 0x10B:    # PE32
        dd = opt + 96
    else:
        return False
    if dd + 14 * 8 + 8 > len(data):
        return False
    com_rva = struct.unpack_from("<I", data, dd + 14 * 8)[0]
    return com_rva != 0


def pick_clr_stub(arch, apc=False, newdomain=False):
    """
    选择 CLR bootstrap 文件名。

    CLR2SC 目前仅提供 x86 的 APC 变体，x64 只有普通 / 新域两种。
    """
    if apc and arch != "x86":
        raise ValueError("APC 模式仅支持 x86（32 位）的 .NET 程序集")
    if apc and newdomain:
        return "clr_x86_newdomain_apc.bin"
    if apc:
        return "clr_x86_apc.bin"
    if newdomain:
        return "clr_x64_newdomain.bin" if arch == "x64" else "clr_x86_newdomain.bin"
    return "clr_x64.bin" if arch == "x64" else "clr_x86.bin"


def build_clr_shellcode(assembly, arch, apc=False, newdomain=False, stub_dir="stub"):
    """
    把 .NET 程序集字节包装为可执行的 shellcode（CLR 内存加载）。

    产物布局：
        [CLR bootstrap（两个长度占位符已填充）][程序集原始字节]

    与 CLR2SC 的生成逻辑一致：
      1. bootstrap 去掉最后一个字节；
      2. 两个 "AAAA" 占位符替换为程序集长度（小端 uint32）；
      3. 程序集字节直接拼接在 bootstrap 之后。
    """
    fname = pick_clr_stub(arch, apc, newdomain)
    path = os.path.join(stub_dir, "clr", fname)
    if not os.path.isfile(path):
        raise FileNotFoundError(
            "找不到 CLR bootstrap %s。请先运行 stub/clr/extract_clr.py 生成（需联网下载 CLR2SC）。"
            % path)
    with open(path, "rb") as f:
        stub = f.read()

    first = stub.find(CLR_PLACEHOLDER)
    if first == -1:
        raise ValueError("CLR bootstrap 缺少第一个长度占位符 (AAAA)")
    second = stub.find(CLR_PLACEHOLDER, first + 1)
    if second == -1:
        raise ValueError("CLR bootstrap 缺少第二个长度占位符 (AAAA)")

    length = len(assembly)
    if length > 0xFFFFFFFF:
        raise ValueError("程序集过大（超过 4GB）")
    len_bytes = struct.pack("<I", length)

    # 去掉最后一个字节（与 CLR2SC 保持一致，保证拼接对齐）
    stub = stub[:-1]

    # 替换两个占位符（均为 4 字节，索引不变）
    stub = stub[:first] + len_bytes + stub[first + 4:]
    stub = stub[:second] + len_bytes + stub[second + 4:]

    return stub + assembly, fname, len(stub)


def build_launcher_cs(assembly_bytes, default_cmd=""):
    """生成 Launcher.cs 源码（内嵌程序集字节，运行时从宿主命令行读参数）。"""
    lines = []
    for i in range(0, len(assembly_bytes), 16):
        chunk = assembly_bytes[i:i + 16]
        lines.append("        " + ", ".join("0x%02X" % b for b in chunk))
    body = ",\n".join(lines)
    default = default_cmd.replace("\\", "\\\\").replace('"', '\\"')

    return """// 自动生成，勿手改。
using System;
using System.Reflection;

class Launcher
{
    static byte[] payload = {
%(body)s
    };

    static void Main(string[] args)
    {
        // 参数来源：宿主进程命令行（cl[0]=宿主exe, cl[1]=shellcode文件, cl[2..]=参数）
        string cmd = null;
        try
        {
            string[] cl = Environment.GetCommandLineArgs();
            if (cl.Length > 2)
                cmd = string.Join(" ", cl, 2, cl.Length - 2);
        }
        catch { }

        if (string.IsNullOrEmpty(cmd))
            cmd = "%(default)s";   // 生成时嵌入的默认参数

        // 目标 Main 的参数：没有命令行时给空数组而不是 null，
        // 这样 Main(string[] args) 拿到的是 string[0]，不会空引用。
        string[] passArgs = string.IsNullOrEmpty(cmd) ? new string[0] : new string[] { cmd };

        Assembly asm;
        try
        {
            asm = Assembly.Load(payload);
        }
        catch (Exception ex)
        {
            Console.WriteLine("[-] Assembly.Load failed: " + ex.GetBaseException().Message);
            return;
        }

        MethodInfo entry = asm.EntryPoint;
        if (entry == null)
        {
            Console.WriteLine("[-] EntryPoint is null (DLL without Main?)");
            return;
        }

        try
        {
            object[] callArgs = entry.GetParameters().Length == 0 ? null : new object[] { passArgs };
            object ret = entry.Invoke(null, callArgs);
            if (ret is int) Environment.Exit((int)ret);   // 和原生运行保持同一退出码
        }
        catch (Exception ex)
        {
            Console.WriteLine("[-] Invoke failed: " + ex.GetBaseException().Message);
        }
    }
}
""" % {"body": body, "default": default}


def find_csc(arch):
    """根据架构返回 csc.exe 路径（.NET Framework 4.x 自带）。"""
    root = os.environ.get("SystemRoot", r"C:\Windows")
    if arch == "x64":
        cand = [os.path.join(root, "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe"),
                os.path.join(root, "Microsoft.NET", "Framework", "v4.0.30319", "csc.exe")]
    else:
        cand = [os.path.join(root, "Microsoft.NET", "Framework", "v4.0.30319", "csc.exe"),
                os.path.join(root, "Microsoft.NET", "Framework64", "v4.0.30319", "csc.exe")]
    for p in cand:
        if os.path.isfile(p):
            return p
    raise FileNotFoundError(
        "找不到 .NET Framework 编译器 csc.exe（需要 .NET Framework 4.x）。"
        "请安装 .NET Framework，或先手动编译 Launcher 再转换。")


def build_launcher(assembly_bytes, arch, default_cmd=""):
    """
    把 .NET 程序集包装成「启动器」程序集并编译，返回编译后的程序集字节。

    启动器内嵌原程序集，运行时从宿主进程命令行读取参数，反射调用目标 Main——
    从而让 .NET 程序集也能像原生 PE 一样命令行传参。
    """
    tmp = tempfile.mkdtemp(prefix="exe2shc_")
    try:
        cs_path = os.path.join(tmp, "Launcher.cs")
        exe_path = os.path.join(tmp, "launcher.exe")
        with open(cs_path, "w", encoding="utf-8") as f:
            f.write(build_launcher_cs(assembly_bytes, default_cmd))

        csc = find_csc(arch)
        platform = "/platform:x64" if arch == "x64" else "/platform:x86"
        env = dict(os.environ)
        env["LIB"] = ""  # 避免无效 LIB 路径导致编译警告
        proc = subprocess.run(
            [csc, "/nologo", "/target:exe", platform,
             "/out:" + exe_path, cs_path],
            capture_output=True, text=True, env=env)
        if proc.returncode != 0:
            raise RuntimeError("Launcher 编译失败：\n%s" % proc.stderr)

        with open(exe_path, "rb") as f:
            return f.read()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _load_packer():
    """惰性导入 tools/pack_b64_lznt1.py（Z85 + LZNT1 打包器）。"""
    tools_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    try:
        import pack_b64_lznt1 as b64pack
    except ImportError as e:
        raise ValueError("需要 tools/pack_b64_lznt1.py 与 nasm：%s" % e)
    return b64pack


def guess_shellcode_arch(data):
    """粗判裸 shellcode 架构：x64 用 gs:[0x60] 取 PEB，x86 用 fs:[0x30]。"""
    head = data[:96]
    x64_mark = bytes([0x65, 0x48, 0x8B])
    x86_mark1 = bytes([0x64, 0xA1, 0x30, 0x00, 0x00, 0x00])
    x86_mark2 = bytes([0x64, 0x8B])
    if x64_mark in head:
        return "x64"
    if x86_mark1 in head or x86_mark2 in head:
        return "x86"
    return "x64"

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="将 Windows EXE 转换为可在内存中执行的 shellcode")
    parser.add_argument("input", help="输入 EXE 文件")
    parser.add_argument("output", nargs="?", default="shellcode.bin",
                        help="输出 shellcode 文件（默认 shellcode.bin）")
    parser.add_argument("--args", "-a", default="",
                        help="默认传给目标程序的命令行参数（运行时由 runner 传入的参数优先）")
    parser.add_argument("--full-cmdline", action="store_true",
                        help="使用 --args 原始内容作为完整命令行（不自动前置程序名）")
    parser.add_argument("--compat", choices=["auto", "on", "off"], default="auto",
                        help="路径/MUI/消息表兼容层：auto=按导入表判断（默认）")
    parser.add_argument("--key-len", type=int, default=0,
                        help="容器模式下节数据的 XOR 密钥长度（默认 0 = 不加密）")
    parser.add_argument("--arch", choices=["auto", "x64", "x86"], default="auto",
                        help="裸 shellcode 的架构（默认 auto 自动识别）")
    parser.add_argument("--stub-dir", default=DEFAULT_STUB_DIR, help="加载桩目录（默认脚本目录下的 stub）")
    parser.add_argument("--apc", action="store_true",
                        help="[.NET] 使用 APC 模式执行（仅支持 x86 程序集）")
    parser.add_argument("--newdomain", action="store_true",
                        help="[.NET] 在新的 AppDomain 中加载程序集")
    parser.add_argument("--launcher", action="store_true",
                        help="[.NET] 强制包装为启动器以支持命令行传参（默认已开启）")
    parser.add_argument("--no-launcher", action="store_true",
                        help="[.NET] 关闭启动器包装，bootstrap 直嵌程序集（目标 Main 收到 null 参数）")
    args = parser.parse_args(argv)

    with open(args.input, "rb") as f:
        data = f.read()

    out_path = os.path.abspath(args.output)

    # .NET 托管程序集：走 CLR 内存加载路径（参考 CLR2SC）
    if is_dotnet(data):
        info = parse_pe(data)
        # AnyCPU 程序集在 64 位系统上本来就按 x64 跑，按 PE machine 判成 x86
        # 会让 payload 以 WOW64 运行，BadPotato 这类会产生 OpenThreadToken 998 失败。
        arch = dotnet_arch(data)
        payload_data = data
        launcher = False
        # 默认就用启动器：CLR bootstrap 的 IDispatch::Invoke 只能安全地传 null 变体，
        # 任何真实 SAFEARRAY 都会在 CLR 侧空指针崩溃（实测），所以参数只能靠托管启动器传。
        if not args.no_launcher:
            try:
                print("[*] 自动包装为启动器（支持命令行传参）...")
                payload_data = build_launcher(data, arch, default_cmd=args.args)
                launcher = True
            except Exception as ex:
                print("[!] 启动器编译失败，回退为 bootstrap 直嵌（目标 Main 收不到参数）：%s" % ex)
        payload, stub_name, stub_len = build_clr_shellcode(
            payload_data, arch, apc=args.apc, newdomain=args.newdomain,
            stub_dir=args.stub_dir)
        payload = _load_packer().wrap(payload, arch)
        packed_mode = "Z85 + LZNT1（%s 自解压桩 + CLR bootstrap）" % arch
        with open(out_path, "wb") as f:
            f.write(payload)

        modes = []
        if launcher:
            modes.append("Launcher 传参")
        if args.apc:
            modes.append("APC")
        if args.newdomain:
            modes.append("New AppDomain")
        print("[+] 类型           : .NET 托管程序集（CLR 内存加载）")
        print("[+] 架构           : %s" % arch)
        print("[+] 加载模式       : %s" % (" + ".join(modes) if modes else "默认（当前 AppDomain）"))
        print("[+] 打包           : %s" % packed_mode)
        print("[+] bootstrap      : %s (%d bytes)" % (stub_name, stub_len))
        print("[+] 程序集大小     : %d bytes" % len(payload_data))
        print("[+] 输出           : %s (%d bytes)" % (out_path, len(payload)))
        print("[+] 目标参数       : %s" % (args.args or "(无 → 目标 Main 收到 string[0])"))
        return

    # 裸 shellcode（非 PE）：Z85 + LZNT1，解压后直接 call
    if data[:2] != b"MZ":
        b64pack = _load_packer()
        sc_arch = args.arch if args.arch != "auto" else guess_shellcode_arch(data)
        if sc_arch == "x86":
            stub = b64pack.assemble_x86()
        else:
            stub = b64pack.assemble(b64pack.DEFAULT_ASM, False, ["RUN_RAW"])
        payload = b64pack.build(stub, data, with_fnv=False)
        with open(out_path, "wb") as f:
            f.write(payload)
        b64len, complen, _rawlen, _ = struct.unpack_from("<IIIQ", payload, len(stub))
        print("[+] 模式           : shellcode（Z85 + LZNT1，解压后直接执行）")
        print("[+] 架构           : %s 位置无关桩" % sc_arch)
        print("[+] 桩大小          : %d bytes" % len(stub))
        print("[+] 载荷大小        : %d bytes" % len(data))
        print("[+] 压缩后          : %d bytes  Z85 后 %d bytes" % (complen, b64len))
        print("[+] 输出            : %s (%d bytes)" % (out_path, len(payload)))
        return

    info = parse_pe(data)

    # 组装命令行：默认把原文件名作为 argv[0] 前置（与 Donut 的 -p 行为一致）
    prog_name = os.path.basename(args.input)
    if args.args:
        cmdline = args.args if args.full_cmdline else "%s %s" % (prog_name, args.args)
    else:
        cmdline = prog_name if not args.full_cmdline else ""
    # ImagePathName 用原始全路径：目标程序调用 GetModuleFileName 时返回它，
    # 依赖自身路径/资源（whoami、tasklist）的程序靠这个找到自己的 .mui
    image_path = os.path.abspath(args.input)



    if info.arch != "x64":
        # x86：Z85 + LZNT1 包住 loader_x86 + 实例块 + 原始 PE
        b64pack = _load_packer()
        inst_block = build_instance_block(cmdline, image_path)
        inner = load_stub(args.stub_dir, info.arch) + inst_block + data
        stub = b64pack.assemble_x86()
        payload = b64pack.build(stub, inner, with_fnv=False)
        cont = inner
        mode = "x86 包装（Z85 + LZNT1 + loader_x86 + 原始 PE）"
    else:
        b64pack = _load_packer()
        cont = b64pack.build_container(data, args.key_len, cmdline,
                                       os.path.abspath(args.input))
        want = {"auto": None, "on": True, "off": False}[args.compat]
        if want is None:
            want = b64pack.needs_compat(data)
        extra = ["RUN_CONTAINER"]
        if not want:
            extra.append("B64_NO_COMPAT")
        stub = b64pack.assemble(b64pack.DEFAULT_ASM, False, extra)
        payload = b64pack.build(stub, cont, with_fnv=False)
        inst_block = b""
        mode = "container（Z85 + LZNT1 + 容器，兼容层%s）" % ("需要" if want else "不需要（已裁剪）")

    with open(out_path, "wb") as f:
        f.write(payload)

    print("[+] 模式           : %s" % mode)
    print("[+] 架构           : %s" % info.arch)
    print("[+] 入口 RVA        : 0x%08X" % info.entry_rva)
    print("[+] ImageBase       : 0x%X" % info.image_base)
    print("[+] SizeOfImage     : 0x%X" % info.size_of_image)
    print("[+] 命令行          : %s" % (cmdline or "(无)"))
    print("[+] ImagePathName   : %s" % image_path)
    print("[+] 桩大小          : %d bytes" % len(stub))
    if cont is not None:
        b64len, complen, rawlen, _ = struct.unpack_from("<IIIQ", payload, len(stub))
        print("[+] 打包前载荷      : %d bytes（原 PE %d）" % (len(cont), len(data)))
        print("[+] 压缩后          : %d bytes  Z85 后 %d bytes" % (complen, b64len))
    else:
        print("[+] 实例块大小      : %d bytes" % len(inst_block))
        print("[+] 原 EXE 大小     : %d bytes" % len(data))
    print("[+] 输出            : %s (%d bytes)" % (out_path, len(payload)))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, FileNotFoundError) as e:
        print("[!] 错误: %s" % e, file=sys.stderr)
        sys.exit(1)

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
runner.py —— 一个极简 shellcode 加载器（等价于 gogogo.exe 的角色）。

用法：
    python runner.py <shellcode.bin> [参数...]

它会把 shellcode 映射到可执行内存，并把「参数」以 UTF-16LE 宽字符串
（Windows 原生命令行编码）通过 CreateThread 的 lpParameter 传给 shellcode。
exe2shc 生成的加载桩会优先采用该运行时参数作为目标程序的 CommandLine。

示例：
    python runner.py 1.bin "D:\\Program Files\\Tencent\\Weixin\\Weixin.exe"
"""

import ctypes
import sys
from ctypes import wintypes

MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
INFINITE = 0xFFFFFFFF

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

kernel32.VirtualAlloc.restype = ctypes.c_void_p
kernel32.VirtualAlloc.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]

kernel32.VirtualFree.restype = wintypes.BOOL
kernel32.VirtualFree.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD]

kernel32.CreateThread.restype = wintypes.HANDLE
kernel32.CreateThread.argtypes = [
    ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
    ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]

kernel32.WaitForSingleObject.restype = wintypes.DWORD
kernel32.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]

kernel32.GetCurrentThreadId.restype = wintypes.DWORD
kernel32.GetCurrentThreadId.argtypes = []

kernel32.GetExitCodeThread.restype = wintypes.BOOL
kernel32.GetExitCodeThread.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]

# ---- 诊断辅助：模块快照 + 线程枚举（在 VEH 里用，必须在跑 shellcode 前先采样）----
_psapi = ctypes.WinDLL("psapi", use_last_error=True)
_psapi.EnumProcessModules.restype = wintypes.BOOL
_psapi.EnumProcessModules.argtypes = [
    wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD)]
_psapi.GetModuleBaseNameW.restype = wintypes.DWORD
_psapi.GetModuleBaseNameW.argtypes = [
    wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
kernel32.GetCurrentProcess.restype = wintypes.HANDLE
kernel32.GetCurrentProcess.argtypes = []

_MODULES = []


def snapshot_modules():
    """记录当前进程已加载模块的地址区间（VEH 里就不能再调 LoadLibrary 了）。"""
    h = kernel32.GetCurrentProcess()
    needed = wintypes.DWORD(0)
    arr = (wintypes.HMODULE * 512)()
    if not _psapi.EnumProcessModules(h, arr, ctypes.sizeof(arr),
                                     ctypes.byref(needed)):
        return
    n = needed.value // ctypes.sizeof(wintypes.HMODULE)
    buf = ctypes.create_unicode_buffer(260)
    for i in range(min(n, 512)):
        base = arr[i]
        _psapi.GetModuleBaseNameW(h, base, buf, 260)
        # 模块大小：用 PE 头里的 SizeOfImage（e_lfanew -> +0x50）
        size = 0
        try:
            e = ctypes.c_uint32.from_address(base + 0x3C).value
            size = ctypes.c_uint32.from_address(base + e + 0x50).value
        except Exception:
            pass
        _MODULES.append((base, size, buf.value))


def resolve_addr(addr):
    """把地址映射成 模块名+偏移 或 shellcode区+偏移。"""
    if not addr:
        return "0"
    for base, size, name in _MODULES:
        if base <= addr < base + max(size, 0x1000):
            return "%s+0x%X" % (name, addr - base)
    if _sc_base and _sc_base <= addr < _sc_base + _sc_size:
        return "SHC+0x%X" % (addr - _sc_base)
    return "0x%X" % addr


def dump_threads():
    th32cs_snapthread = 0x00000004
    THREADENTRY32 = type("THREADENTRY32", (ctypes.Structure,), {
        "_fields_": [("dwSize", wintypes.DWORD),
                     ("cntUsage", wintypes.DWORD),
                     ("th32ThreadID", wintypes.DWORD),
                     ("th32OwnerProcessID", wintypes.DWORD),
                     ("tpBasePri", ctypes.c_long),
                     ("tpDeltaPri", ctypes.c_long),
                     ("dwFlags", wintypes.DWORD)]})
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.Thread32First.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.Thread32Next.argtypes = [wintypes.HANDLE, ctypes.POINTER(THREADENTRY32)]
    kernel32.OpenThread.restype = wintypes.HANDLE
    kernel32.OpenThread.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.GetCurrentProcessId.restype = wintypes.DWORD
    kernel32.GetCurrentProcessId.argtypes = []

    ntdll = ctypes.WinDLL("ntdll")
    pid = kernel32.GetCurrentProcessId()
    snap = kernel32.CreateToolhelp32Snapshot(th32cs_snapthread, 0)
    if snap in (0, None):
        return
    te = THREADENTRY32()
    te.dwSize = ctypes.sizeof(te)
    ok = kernel32.Thread32First(snap, ctypes.byref(te))
    print("      --- 进程 %d 的线程 ---" % pid)
    while ok:
        if te.th32OwnerProcessID == pid:
            addr = 0
            h = kernel32.OpenThread(0x0040, False, te.th32ThreadID)  # QUERY_INFORMATION
            if h:
                out = ctypes.c_void_p(0)
                ret = ntdll.NtQueryInformationThread(ctypes.c_void_p(h), 9,
                                                     ctypes.byref(out), 8, None)
                if ret == 0:
                    addr = out.value or 0
                kernel32.CloseHandle(h)
            print("        tid=%-6d start=%s" % (te.th32ThreadID, resolve_addr(addr)))
        te.dwSize = ctypes.sizeof(te)
        ok = kernel32.Thread32Next(snap, ctypes.byref(te))
    kernel32.CloseHandle(snap)


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [
        ("ExceptionCode", wintypes.DWORD),
        ("ExceptionFlags", wintypes.DWORD),
        ("ExceptionRecord", ctypes.c_uint64),
        ("ExceptionAddress", ctypes.c_uint64),
        ("NumberOfParameters", wintypes.DWORD),
        ("ExceptionInformation", ctypes.c_uint64 * 15),
    ]


class EXCEPTION_POINTERS(ctypes.Structure):
    _fields_ = [
        ("ExceptionRecord", ctypes.POINTER(EXCEPTION_RECORD)),
        ("ContextRecord", ctypes.c_void_p),
    ]


class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("P1Home", ctypes.c_uint64), ("P2Home", ctypes.c_uint64),
        ("P3Home", ctypes.c_uint64), ("P4Home", ctypes.c_uint64),
        ("P5Home", ctypes.c_uint64), ("P6Home", ctypes.c_uint64),
        ("ContextFlags", ctypes.c_uint32), ("MxCsr", ctypes.c_uint32),
        ("SegCs", ctypes.c_uint16), ("SegDs", ctypes.c_uint16),
        ("SegEs", ctypes.c_uint16), ("SegFs", ctypes.c_uint16),
        ("SegGs", ctypes.c_uint16), ("SegSs", ctypes.c_uint16),
        ("EFlags", ctypes.c_uint32),
        ("Dr0", ctypes.c_uint64), ("Dr1", ctypes.c_uint64),
        ("Dr2", ctypes.c_uint64), ("Dr3", ctypes.c_uint64),
        ("Dr6", ctypes.c_uint64), ("Dr7", ctypes.c_uint64),
        ("Rax", ctypes.c_uint64), ("Rcx", ctypes.c_uint64),
        ("Rdx", ctypes.c_uint64), ("Rbx", ctypes.c_uint64),
        ("Rsp", ctypes.c_uint64), ("Rbp", ctypes.c_uint64),
        ("Rsi", ctypes.c_uint64), ("Rdi", ctypes.c_uint64),
        ("R8", ctypes.c_uint64), ("R9", ctypes.c_uint64),
        ("R10", ctypes.c_uint64), ("R11", ctypes.c_uint64),
        ("R12", ctypes.c_uint64), ("R13", ctypes.c_uint64),
        ("R14", ctypes.c_uint64), ("R15", ctypes.c_uint64),
        ("Rip", ctypes.c_uint64),
    ]


VECTORED_HANDLER = ctypes.WINFUNCTYPE(
    wintypes.LONG, ctypes.POINTER(EXCEPTION_POINTERS))

kernel32.AddVectoredExceptionHandler.restype = ctypes.c_void_p
kernel32.AddVectoredExceptionHandler.argtypes = [wintypes.ULONG, VECTORED_HANDLER]

# 读内存前先用 VirtualQuery 校验，切勿在 VEH 里直接读写野指针：
# 在异常处理过程中再触发访问违例会变成嵌套异常，原异常就永远到不了 SEH（目标程序
# 里靠 __try/__except 捕获自己触发的异常的代码会被直接打死）。
MEM_COMMIT = 0x1000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


kernel32.VirtualQuery.restype = ctypes.c_size_t
kernel32.VirtualQuery.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]


def _readable_span(addr, want):
    """返回 addr 处实际可安全读取的字节数（0 表示不可读）。"""
    if not addr or addr < 0x10000:
        return 0
    try:
        mbi = MEMORY_BASIC_INFORMATION()
        if not kernel32.VirtualQuery(ctypes.c_void_p(addr),
                                     ctypes.byref(mbi), ctypes.sizeof(mbi)):
            return 0
        if mbi.State != MEM_COMMIT:
            return 0
        if mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD):
            return 0
        avail = (mbi.BaseAddress + mbi.RegionSize) - addr
        return max(0, min(want, avail))
    except Exception:
        return 0


def _read_u64(addr):
    if _readable_span(addr, 8) < 8:
        return 0
    return ctypes.c_uint64.from_address(addr).value


def _read_wstr(addr, max_chars=256):
    """安全读 addr 指向的 UTF-16LE 字符串，最多 max_chars 个字符。"""
    n = _readable_span(addr, max_chars * 2)
    if n < 2:
        return None
    raw = ctypes.string_at(addr, n - (n % 2))
    return raw.decode("utf-16-le", "replace").split("\x00")[0]


EXCEPTION_CONTINUE_SEARCH = 0
_sc_base = 0
_sc_size = 0
_veh_callback = None  # 保持回调引用，避免被 GC
_cont_callback = None
_dumped = False


def _veh(info_ptr):
    rec = info_ptr.contents.ExceptionRecord.contents
    ctx = ctypes.cast(info_ptr.contents.ContextRecord,
                      ctypes.POINTER(CONTEXT)).contents
    print("[VEH] code=0x%08X rip=0x%X (%s) off=0x%X tid=%d" % (
        rec.ExceptionCode, rec.ExceptionAddress, resolve_addr(rec.ExceptionAddress),
        rec.ExceptionAddress - _sc_base if _sc_base else 0,
        kernel32.GetCurrentThreadId()))
    print("      rbx=0x%X rbp=0x%X rax=0x%X r10=0x%X" % (
        ctx.Rbx, ctx.Rbp, ctx.Rax, ctx.R10))
    print("      rdi=0x%X rsi=0x%X rsp=0x%X" % (ctx.Rdi, ctx.Rsi, ctx.Rsp))
    print("      r8=0x%X r9=0x%X r11=0x%X rcx=0x%X rdx=0x%X" % (
        ctx.R8, ctx.R9, ctx.R11, ctx.Rcx, ctx.Rdx))
    print("      [rsp+0x48]=0x%X [rsp+0x50]=0x%X [rsp+0x58]=0x%X" % (
        _read_u64(ctx.Rsp + 0x48), _read_u64(ctx.Rsp + 0x50),
        _read_u64(ctx.Rsp + 0x58)))
    s = _read_wstr(ctx.Rax)
    if s is not None:
        print("      rax->: %r" % s)
    # 栈回溯线索：把栈上像地址的 qword 打出来（ntdll 0x7FF... / 已映射映像地址）
    try:
        words = [_read_u64(ctx.Rsp + 8 * i) for i in range(32)]
        addrs = [w for w in words if w > 0x10000]
        if addrs:
            print("      stack: " + " ".join("%X" % w for w in addrs))
    except Exception:
        pass
    global _dumped
    if not _dumped:
        _dumped = True
        try:
            dump_threads()
        except Exception as ex:
            print("      (dump_threads 失败: %r)" % ex)
    return EXCEPTION_CONTINUE_SEARCH


# Vectored Continue Handler：只在「SEH 链没有处理」时才会被调用。
# 用它判断目标程序里的 __try/__except 到底有没有被派发到。
kernel32.AddVectoredContinueHandler.restype = ctypes.c_void_p
kernel32.AddVectoredContinueHandler.argtypes = [wintypes.ULONG, VECTORED_HANDLER]

_cont_callback = None


def _veh_continue(info_ptr):
    rec = info_ptr.contents.ExceptionRecord.contents
    print("[VCH] SEH 未处理: code=0x%08X rip=0x%X" % (
        rec.ExceptionCode, rec.ExceptionAddress))
    return EXCEPTION_CONTINUE_SEARCH


def main(argv):
    if len(argv) < 2:
        print("用法: python runner.py <shellcode.bin> [参数...]")
        return 1

    bin_path = argv[1]
    with open(bin_path, "rb") as f:
        sc = f.read()

    # 可选：运行时参数（UTF-16LE，以 \0\0 结尾）
    # 含空格的参数自动加引号（loader 按引号分组解析为单个 argv）
    arg_parts = []
    for a in argv[2:]:
        if ' ' in a or '\t' in a:
            arg_parts.append('"%s"' % a)
        else:
            arg_parts.append(a)
    args_str = " ".join(arg_parts)
    param = (args_str + "\0").encode("utf-16-le") if args_str else None

    total = len(sc) + (len(param) if param else 0)

    addr = kernel32.VirtualAlloc(
        None, total, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    if not addr:
        print("[!] VirtualAlloc 失败，错误码 %d" % ctypes.get_last_error())
        return 1

    global _sc_base, _sc_size, _veh_callback
    _sc_base = addr
    _sc_size = len(sc)
    _veh_callback = VECTORED_HANDLER(_veh)
    kernel32.AddVectoredExceptionHandler(1, _veh_callback)

    global _cont_callback
    _cont_callback = VECTORED_HANDLER(_veh_continue)
    kernel32.AddVectoredContinueHandler(1, _cont_callback)

    ctypes.memmove(addr, sc, len(sc))
    param_ptr = None
    if param:
        param_ptr = addr + len(sc)
        ctypes.memmove(param_ptr, param, len(param))

    tid = wintypes.DWORD(0)
    h = kernel32.CreateThread(None, 0, addr, param_ptr, 0, ctypes.byref(tid))
    if not h:
        print("[!] CreateThread 失败，错误码 %d" % ctypes.get_last_error())
        kernel32.VirtualFree(addr, 0, 0x8000)  # MEM_RELEASE
        return 1

    print("[*] 主线程 tid=%d" % kernel32.GetCurrentThreadId())
    try:
        snapshot_modules()
        for base, size, name in _MODULES:
            print("    模块 %016X size=0x%X %s" % (base, size, name))
    except Exception as ex:
        print("[!] snapshot_modules 失败: %r" % ex)
    print("[*] 已启动线程，shellcode @ 0x%X，参数: %r" % (addr, args_str or None))
    kernel32.WaitForSingleObject(h, INFINITE)

    code = wintypes.DWORD(0)
    kernel32.GetExitCodeThread(h, ctypes.byref(code))
    print("[*] shellcode 线程已结束，退出码=0x%08X (tid=%d)" % (
        code.value, tid.value))

    kernel32.VirtualFree(addr, 0, 0x8000)  # MEM_RELEASE
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

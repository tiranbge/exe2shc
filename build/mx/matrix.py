# -*- coding: utf-8 -*-
"""打包 -> 运行 -> 对比 回归矩阵。"""
import os, subprocess, sys, re
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BAN = re.compile(r"^(\[\*\] Reading module|>>> Creating a new thread|\[\*\] Running the shellcode)")

CASES = [
    # name,                  exe,                        args,        runner, packflags,  sig,                       exit
    ("C x64 容器",       "build/mx/c_hello.exe",  "a b", "runshc64", "",        "C-HELLO argc=3",  7),
    ("argv 三源 容器",   "build/mx/cl_dump.exe",  "a b", "runshc64", "",        "argc=3 argv0=[cl_dump.exe]", 0),
    ("C x64 引号参数",   "build/mx/c_hello.exe",  '"x y" z', "runshc64", "",  "arg[1]=x y",      7),
    ("Go x86 带参",      "build/mx/go32.exe",     "1 2", "runshc32", "",        "GO-HELLO args=2", 5),
    ("argv x86 包装",    "build/mx/go_probe32.exe", "p q", "runshc32", "",      "OSARGS=3",        0),
    ("argv x64 容器",    "build/mx/go_probe64.exe", "p q", "runshc64", "",      "OSARGS=3",        0),
    ("C++ EH 容器",      "build/mx/cpp_eh.exe",   "",    "runshc64", "",        "CPP-DONE got=42", 0),
    ("C TLS 容器",       "build/mx/c_tls.exe",    "",    "runshc64", "",        "TLS-VAR 1235",    0),
    ("Go x64 容器",      "build/mx/go64.exe",     "x y", "runshc64", "",        "GO-HELLO args=2", 5),
    ("Rust x64 容器",    "build/mx/rs64.exe",     "m n", "runshc64", "",        "RS-HELLO args=2", 6),
    ("comreg 容器",      "samples/comreg.exe",            "-u {11111111-1111-1111-1111-111111111111}", "runshc64", "", "-] 已卸载", 0),
    ("hostname 容器",    "C:/Windows/System32/hostname.exe", "", "runshc64", "", "Lenovo", 0),
    ("mimikatz 容器",    "samples/mimikatz.exe",          "exit","runshc64", "",        "Bye!",            0),
    ("Go x86 包装",      "build/mx/go32.exe",     "q",   "runshc32", "",        "GO-HELLO args=1", 5),
    ("where x86 包装",   "C:/Windows/SysWOW64/where.exe", "", "runshc32", "",   "",                None),
    (".NET AnyCPU",      "build/mx/cs_any.exe",   "",    "runshc64", "",        "bits=64 args=0",  4),
    (".NET x64",         "build/mx/cs_x64.exe",   "",    "runshc64", "",        "bits=64 args=0",  4),
    (".NET x86",         "build/mx/cs_x86.exe",   "",    "runshc32", "",        "bits=32 args=0",  4),
    ("whoami x86 包装",  "C:/Windows/SysWOW64/whoami.exe", "", "runshc32", "", "\\", 0),
    ("where x86 带参",   "C:/Windows/SysWOW64/where.exe", "cmd", "runshc32", "", "System32", 0),
    ("whoami 容器",      "C:/Windows/System32/whoami.exe", "", "runshc64", "", "\\",             0),
    ("tasklist 容器",    "C:/Windows/System32/tasklist.exe", "", "runshc64", "", "System Idle Process", 0),
    ("tasklist x86 包装", "C:/Windows/SysWOW64/tasklist.exe", "", "runshc32", "", "Mem Usage", 0),
    ("where 容器",       "C:/Windows/System32/where.exe", "cmd", "runshc64", "", "System32",        0),
    ("quser 容器",       "C:/Windows/System32/quser.exe", "", "runshc64", "", "console",          0),
]

def run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=180)
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    lines = [l for l in out.replace("\r\n", "\n").split("\n") if l and not BAN.match(l)]
    return p.returncode, "\n".join(lines)

def native_exit(exe, args):
    if not os.path.exists(os.path.join(REPO, exe)):
        return None
    try:
        p = subprocess.run([os.path.join(REPO, exe)] + ([args] if args else []), cwd=REPO,
                           capture_output=True, timeout=120)
        return p.returncode
    except Exception:
        return None

ok = bad = 0
rows = []
for name, exe, args, runner, flags, sig, want in CASES:
    out_bin = "build/mx/out_%s.bin" % re.sub(r"\W+", "_", name)
    pack = [sys.executable, "exe2shc.py", exe, out_bin]
    if args:
        pack += ["--args", args]
    if flags:
        pack += flags.split()
    p = subprocess.run(pack, cwd=REPO, capture_output=True)
    if p.returncode != 0:
        rows.append((name, "PACK-FAIL", p.stderr.decode("utf-8", "replace")[:120], ""))
        bad += 1
        continue
    code, text = run([os.path.join(REPO, runner + ".exe"), out_bin], REPO)
    if want is None:
        want = native_exit(exe, args)
        want = 0 if want is None else want
    hitsig = sig in text if sig else bool(text.strip())
    okc = (code == want) and hitsig
    if okc:
        ok += 1
    else:
        bad += 1
    rows.append((name, "exit=%d(want %d)" % (code, want), "sig " + ("OK" if hitsig else "MISS"), text.strip().split("\n")[0][:60]))

w = max(len(r[0]) for r in rows)
for name, code, sig, first in rows:
    print("%-*s  %-18s %-10s %s" % (w, name, code, sig, first))
print("\n%d ok / %d fail" % (ok, bad))

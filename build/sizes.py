import io
import os
import re
import subprocess
import sys

PY = sys.executable
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
samples = [
    "samples/AxHunter_v1.exe",
    "samples/mimikatz.exe",
    "samples/fscan.exe",
    "samples/badpotato.exe",
    "build/dotnet32.exe",
    "samples/comreg.exe",
    "build/argv64.exe",
    r"C:\Windows\SysWOW64\hostname.exe",
]
for s in samples:
    out = os.path.join("build", "size_" + os.path.basename(s) + ".bin")
    env = dict(os.environ, PYTHONIOENCODING="utf-8", MSYS_NO_PATHCONV="1")
    r = subprocess.run([PY, "exe2shc.py", s, out], cwd=ROOT, env=env,
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    txt = r.stdout + r.stderr
    def grab(pat):
        m = re.search(pat, txt)
        return m.group(1) if m else "?"
    print("%-30s in=%-9s cont=%-9s comp=%-9s prod=%s" % (
        os.path.basename(s),
        os.path.getsize(os.path.join(ROOT, s)) if os.path.exists(os.path.join(ROOT, s)) else "?",
        grab(r"打包前载荷\s*: (\d+)"),
        grab(r"压缩后\s*: (\d+)"),
        grab(r"输出\s*: .*\((\d+) bytes\)"),
    ))

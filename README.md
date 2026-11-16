# exe2shc

把 Windows PE / .NET 程序集 / 裸 shellcode 打包成**可内存执行**的 shellcode。

产物是「自解压桩 + 元数据 + Z85 文本」的位置无关二进制：调用方 `VirtualAlloc(RWX)` 一块内存、
把产物拷进去再 `call` 起点即可，磁盘上不需要落地任何文件。

- 打包器纯 Python 标准库实现，无第三方依赖
- 自动识别四条输入链路：x64 PE、x86 PE、.NET 程序集、裸 shellcode
- 运行时改写 PEB 里的 `CommandLine` / `ImagePathName`，目标程序能正常拿到 argv
- 可选兼容层，修 `GetModuleFileNameW` / MUI 资源 / `FormatMessageW` 文案
- 压缩用 LZNT1 + [Z85](https://rfc.zeromq.org/spec/32/)（膨胀 1.250×，base64 是 1.333×）

> 仅用于**已获授权**的安全测试、教学与研究。请勿用于未授权的目标。

---

## 快速开始

环境：Windows + Python 3.8+（打包端需要 `ntdll!RtlCompressBuffer`，只能在 Windows 上跑），
以及 [NASM](https://www.nasm.us/)（运行时汇编解密桩）。仓库自带一份 nasm 时优先用它，
否则回退到 `PATH` 里的 `nasm`。

```bat
:: 1) 打包：PE -> shellcode
python exe2shc.py C:\Windows\System32\whoami.exe whoami.bin

:: 2) 运行：自带的调试运行器，在当前 Python 进程里起线程执行
python runner.py whoami.bin
```

也可以用第三方运行器 `runshc64.exe`（自行下载后放仓库根目录，见下文「运行产物」）：

```bat
.\runshc64.exe whoami.bin
```

`runner.py` 只在**同位数**的解释器下能跑对应产物：x64 产物用 64 位 Python，x86 产物用 32 位 Python。

## 四种输入链路

| 输入 | 判据 | 产物构成 | 谁负责映射 |
|---|---|---|---|
| x64 PE | `MZ` + machine `0x8664` | `x64 解密桩` + 容器（`Z85+LZNT1`） | 解密桩自己建镜像 |
| x86 PE | `MZ` + machine `0x014C` | `x86 解密桩` + `Z85+LZNT1(loader_x86 + 实例块 + 原始 PE)` | 解压后交给 `loader_x86` |
| .NET 程序集 | `MZ` + CLR 目录 | `解密桩` + `Z85+LZNT1(CLR bootstrap + 启动器程序集)` | CLR bootstrap 拉起运行时 |
| 裸 shellcode | 不是 `MZ` | `解密桩` + `Z85+LZNT1(原始字节)` | 桩解压完直接 `call` |

x64 的「容器」是把 PE 拆开重新排的紧凑结构（`SizeOfImage` / `EntryRVA` / `ImageBase` / 导入表与
重定位目录 / TLS 目录 / `.pdata` / PE 头原文 / 紧排后的节数据 / 目标命令行 / 镜像全路径），
体积比原 PE 小，桩按它一次性 `VirtualAlloc` 建镜像、回写头、按节拷贝、做重定位和导入、注册
异常表、建 TLS、改命令行，最后 `call image+EntryRVA`，返回即 `ExitProcess(0)`。

细节（容器字段偏移、兼容层、x86 包装、.NET 启动器、实测数据、限制）都在
[docs/container_layer.md](docs/container_layer.md)。

## 命令行

```
python exe2shc.py <输入> [输出] [选项]
```

| 参数 | 说明 |
|---|---|
| `输入` | PE/EXE、.NET 程序集，或裸 shellcode 文件 |
| `输出` | 输出文件，默认 `shellcode.bin` |
| `-a`, `--args` | 打包时写入的默认命令行；运行时由运行器传入的参数优先 |
| `--full-cmdline` | 把 `--args` 原样当成完整命令行（不自动前置程序文件名） |
| `--compat {auto,on,off}` | 路径 / MUI / 消息表兼容层，`auto`（默认）按导入表判断是否编入 |
| `--key-len N` | 容器模式下节数据的 XOR 密钥长度，默认 `0`（不加密） |
| `--arch {auto,x64,x86}` | 仅裸 shellcode：目标架构，默认按首字节粗判 |
| `--stub-dir` | 加载桩目录，默认脚本旁边的 `stub/` |
| `--apc` | [.NET] 用 APC 方式执行引导桩（仅 x86 程序集） |
| `--newdomain` | [.NET] 在新的 AppDomain 中加载程序集 |
| `--no-launcher` | [.NET] 不做启动器包装，bootstrap 直嵌程序集（目标 `Main` 收不到参数） |

### 例子

```bat
:: x64 容器模式（默认 + 自动判断兼容层）
python exe2shc.py samples\mimikatz.exe m.bin
python exe2shc.py samples\mimikatz.exe m.bin -a "exit"

:: x86：Z85+LZNT1 包住 loader_x86 + 原始 PE
python exe2shc.py C:\Windows\SysWOW64\whoami.exe whoami32.bin

:: .NET：默认编译托管启动器，命令行由启动器透传给目标 Main
python exe2shc.py samples\badpotato.exe bp.bin -a "whoami /priv"

:: 裸 shellcode（payload.bin 是任意位置的原始 shellcode）
python exe2shc.py payload.bin raw.bin --arch x64
```

上面的 `samples\` 是**本地**样本目录（不入库），换成自己的 PE 即可。

运行时参数优先于 `--args`：

```bat
:: 用打包时写入的默认命令行
.\runshc64.exe whoami.bin

:: 运行时把参数覆盖成 "whoami /all"
.\runshc64.exe whoami.bin /all
```

## 运行产物

产物没有任何文件格式，就是一段位置无关代码，入口在偏移 0。要求：

- 放进可读写可执行的内存（`PAGE_EXECUTE_READWRITE`），或者先 `VirtualProtect` 再执行；
- 从**新线程**执行（桩内部会改当前线程的 TEB/TLS 状态并 `ExitProcess`，别占着宿主主线程）；
- 参数通过线程的 `lpParameter` 传：指向 UTF-16LE 命令行的指针，`NULL` 表示用打包时的默认值。
  见 `runner.py` 里的 `CreateThread(..., lpParameter=cmdline_buf, ...)`。

`runshc64.exe` / `runshc32.exe` 是第三方运行器（hasherezade/runshc），**不在本仓库内**，
需要时自行下载后放到仓库根目录；`runner.py` 是等价的简易实现，带 VEH/模块/线程诊断。

## 兼容层（`--compat`）

容器模式会把镜像私有映射到内存，于是这几类 API 会退化：

| 现象 | 修法 |
|---|---|
| `GetModuleFileNameW` 拿到宿主 exe 路径 | 打包时把原 exe 全路径写进容器，桩按路径造宽串返回 |
| `LoadStringW` / 资源查找失败（.mui） | 打包期把 MUI 候选路径算好，桩在 `user32` 里挂钩 `LoadStringW` 等 |
| `FormatMessageW(FROM_HMODULE)` 文案全空（ipconfig/route/netstat 静默） | 用 `LoadLibraryExW(..., LOAD_LIBRARY_AS_DATAFILE)` 的句柄替代自建镜像句柄 |

`--compat auto` 只在目标导入表命中这些函数时才编入兼容代码，否则用 `-DB64_NO_COMPAT` 裁剪
（约省 1.6KB）。实测 `comreg` / `mimikatz` / `fscan` 不需要兼容层，`hostname` / `whoami` /
`tasklist` / `systeminfo` / `ipconfig` 需要。

## 体积实测

容器模式 vs 裸 PE 直压（LZNT1+Z85 后的最终产物）：

| 载荷 | 原 PE | 容器模式 | 裸 PE 模式 | 差 |
|---|---|---|---|---|
| `comreg.exe` | 5,632 | 5,516 | 5,968 | −7.6% |
| `hostname.exe` | 40,960 | 12,752 | 15,764 | −19.1% |
| `mimikatz.exe` | 1,250,056 | 1,108,932 | 1,121,236 | −1.1% |

`--key-len 11` 这类节数据 XOR 会把压缩率打掉（mimikatz 压缩后 830K → 1101K，+33%），
所以默认不加密。

## 目录结构

```
exe2shc.py              打包器（CLI 入口）
runner.py               简易 shellcode 运行器（ctypes，调试用）
stub/
  dec_b64_lznt1.asm     x64 解密桩：Z85 -> LZNT1 -> 建容器镜像 / 直接执行
  dec_b64_lznt1_x86.asm x86 解密桩
  loader_x64.asm        x64 常规加载器（裸 PE 模式、示例）
  loader_x64.bin        上面这个加载器的预编译产物（已入库）
  loader_x86.asm        x86 包装模式加载器
  loader_x86.bin        x86 加载器的预编译产物（已入库）
  build.bat/.sh         用 nasm 重新汇编上面两个 .bin
  clr/extract_clr.py    从 CLR2SC 页面提取 6 个 CLR 引导桩
tools/
  pack_b64_lznt1.py     Z85 / LZNT1 / 容器构造 / nasm 调用
  runner_x86.ps1        x86 产物的 PowerShell 运行脚本
docs/container_layer.md 设计文档：容器布局、兼容层、实测矩阵、限制
examples/loader_b64_demo.asm 带容器支持的 loader 示例
build/                  测试探针源码（C / C++ / Go / Rust / C#）与本地编译产物
build/mx/matrix.py      回归矩阵：批量打包 + 跑 + 比对退出码与关键字
build/sizes.py          体积对比脚本
samples/                本地测试样本（不入库）
```

## 首次使用 / 重新生成

`stub/loader_x64.bin` / `stub/loader_x86.bin` 已预编译入库，clone 下来直接可用。只有改过
`loader_*.asm` 之后才需要重新汇编（产物与源码逐字节可复现）：

```bat
cd stub && build.bat && cd ..
```

只有 .NET 输入才需要 CLR 引导桩，6 个 `clr_*.bin` 是 CLR2SC 的派生物、不入库：

```bat
:: 从 https://github.com/Laster-dev/CLR2SC 把 index.html 存为 stub\clr\clr2sc_index.html
python stub\clr\extract_clr.py
```

x64 / .NET / 裸 shellcode 链路在每次打包时用 nasm 现场汇编解密桩，所以 nasm 是硬依赖；
仓库自带的 `tools/nasm-2.16.03/nasm.exe` 优先使用，缺失则回退到 `PATH`。

## 已知限制

- **没有重定位表的 PE 只能落在首选基址**：镜像被占用时退回随机基址后无法重定位；
- **TLS 只在当前线程建立**：桩不会为新线程复制 TLS 槽，依赖 `thread_local` 的目标需要自己处理；
- **容器只回写 `[0, SizeOfHeaders)` 的 PE 头**：调试器/工具读镜像时看到的是被改过的头；
- **x86 包装模式**里 `SysWOW64` → `System32` 的等长路径替换只覆盖常见程序（whoami/tasklist 等）；
- **.NET 参数的通道是启动器**：直嵌模式下 `Main` 拿不到 argv；
- 产物按「当前进程内新建线程」设计，不要塞进已经跑着 CLR / 大量线程的宿主里。

## 回归测试

```bat
python build\mx\matrix.py
python build\sizes.py
```

`matrix.py` 跑 25 个用例：打包 -> `runshc64/32` 执行 -> 比对退出码与关键字，最后打印
`N ok / M fail`；`sizes.py` 输出体积对比表。

矩阵里涉及 `samples/` 的用例需要本地放好样本（mimikatz、comreg 等），其余用例用
`build/` 下自编译的探针程序，覆盖 C / C++ 异常 / TLS / Go / Rust / .NET（AnyCPU、x64、x86）、
带引号的参数、x86 包装等场景。

## 参考

- CLR 引导桩思路：[Laster-dev/CLR2SC](https://github.com/Laster-dev/CLR2SC)
- 运行器：[hasherezade/runshc](https://github.com/hasherezade/runshc)
- 编码：Z85（ZeroMQ RFC 32）；压缩：`ntdll!RtlCompressBuffer`（LZNT1）

## 许可

[MIT](LICENSE)。捆绑/引用的第三方组件（NASM、CLR2SC 引导桩、runshc 运行器）分别遵循其自身许可。

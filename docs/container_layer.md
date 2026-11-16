# 容器层（container layer）

把 PE 压成「精简中间表示」，让 stub 自己重建镜像，不再需要 `loader_x64.asm` 那套文件式 PE 解析。
思路来自样本 `payload_x64(1).bin`：它的 stub 解完 base64 + RC4 + LZNT1 拿到的不是 PE，而是一个
`0x6C` 头的自定义容器（SizeOfImage / 入口 RVA / 节表 / 导入表 RVA / 重定位表 RVA / 3 把 XOR 密钥 +
紧排节数据）。

## 1. 容器布局

小端，紧排：

| 偏移 | 类型 | 含义 |
|---|---|---|
| +0x00 | u32 | SizeOfImage |
| +0x04 | u32 | EntryRVA |
| +0x08 | u64 | ImageBase（首选基址） |
| +0x10 | u32 | ImportRVA（导入表目录 RVA） |
| +0x14 | u32 | RelocRVA（重定位表目录 RVA） |
| +0x18 | u32 | RelocSize |
| +0x1C | u32 | TlsRVA（0 = 没有 TLS 目录） |
| +0x20 | u32 | TlsSize |
| +0x24 | u32 | PdataRVA（0 = 没有异常表） |
| +0x28 | u32 | PdataSize |
| +0x2C | u32 | HdrSize（回写镜像的 PE 头字节数，0 = 不写） |
| +0x30 | u32 | HdrOff（PE 头在容器里的偏移） |
| +0x34 | u32 | NSect |
| +0x38 | u32 | KeyLen（0 = 节数据不加密） |
| +0x3C | bytes | Key[KeyLen] |
| +0x3C+KeyLen | NSect × {u32 RVA, u32 DataOff, u32 RawSize} | 节表，DataOff 相对容器起点 |
| 之后 | u32 CmdLen + UTF-16LE | 命令行块（CmdLen 为 0 时用内置 "X.exe"） |
| 之后 | u32 ModPathLen + UTF-16LE | 原始 exe 全路径（0 = 不做路径兼容层） |
| 之后 | u32 MuiTotal + N×(u32 len + UTF-16LE) | MUI 候选路径（打包机算好：`<dir>\zh-CN\<name>.mui`、`<dir>\en-US\<name>.mui`） |
| 之后 | bytes | PE 头原文（HdrSize 字节，从文件偏移 0 开始整段拷贝） |
| 之后 | bytes | 各节数据按节表顺序紧排，每节独立按 Key 循环 XOR |

和样本的差别：节数可变（样本硬编码 5 节）、单把密钥（样本 3 把，5/7/9 字节）、头从 0x3C 起（样本 0x6C）、
ImageBase 存 64 位（样本 `0x80000000` 是 32 位值）、多了 TLS / 异常表 / PE 头字段。

砍掉的东西：`FileAlignment` 填充、`VirtualSize > RawSize` 的尾部空洞、数据目录里的其余项
（只保留导入、重定位、TLS、异常表四项 RVA）。**PE 头本身以原文形式放在容器尾部**，
stub 建完镜像先把它 memcpy 回 `[ImageBase, ImageBase+HdrSize)` —— 因为 mingw CRT 的
`_pei386_runtime_relocator` 会解析自身 PE 头找 `.reloc` 目录，头缺失时整段解释器初始化就废了。

## 1.1 stub 侧做的事（`-DRUN_CONTAINER`）

`b64_load_and_run` 的顺序，缺一不可：

1. `b64_build_image`：`VirtualAlloc(ImageBase, SizeOfImage)`（失败退随机基址）→ 回写 PE 头 → 按节表 memcpy + XOR 解密；
2. `b64_reloc`：`delta = 实际基址 - ImageBase`，按 DIR64/HIGHLOW 项修补；
3. `b64_imports`：遍历 `IMAGE_IMPORT_DESCRIPTOR`，`LoadLibraryA` + `GetProcAddress` 写 IAT；
4. **注册 `.pdata`**：`LoadLibraryA("ntdll.dll")` → `GetProcAddress("RtlAddFunctionTable")`
   → `(image+PdataRVA, PdataSize/12, image)`。x64 的 SEH 是表驱动的，没这一步 `__try/__except`
   和 C++ 异常全部失效；mingw CRT 的启动流程也会因此崩在收尾；
5. `b64_tls`：`TlsAlloc()` → 把索引写进 `AddressOfIndex` → 按模板（`End-Start + SizeOfZeroFill`）
   `VirtualAlloc(RW)` + memcpy → 写 `TEB(+0x58)->ThreadLocalStoragePointer[index]` →
   依次调用 `AddressOfCallBacks` 里的回调 `(image, DLL_PROCESS_ATTACH, 0)`；
6. `b64_fix_cmdline`：把容器里的命令行覆盖进 PEB `CommandLine.Buffer` 并补 NUL；
7. `call image + EntryRVA`。

> 踩过的坑：x64 调用约定给被调方留了 32 字节 shadow space（`[rsp+0]`~`[rsp+0x18]`），
> 局部变量放在这段里会被 `VirtualAlloc` 之类的调用原地覆盖（表现为 `TlsAlloc` 的索引变成指针低 32 位、
> 循环计数器乱跳）。所有桩内函数的局部变量都从 `[rsp+0x20]` 起放。


### 1.3 x86 包装路径（`loader_x86.asm`）

x86 侧不能像 x64 那样靠"解析到的函数地址相等"来识别 IAT 槽位：`tasklist.exe` 之类把
`LoadStringW` 从 `api-ms-win-core-libraryloader-l1-2-0.dll` 导入，解析结果与
`user32!LoadStringW` 不是同一个句柄。因此 x86 的 IAT 遍历改成**按导入名匹配**
（读 `OriginalFirstThunk` 的 hint/name，用 `hk_streq` 比较 `GetModuleFileNameW` / `LoadStringW`）。

两条容易踩的坑：

1. `OriginalFirstThunk == 0` 的描述符要直接跳过，否则会把 IAT 里的函数地址当字符串指针扫；
2. 名字指针在 OFT 里是 **RVA**，必须先 `add eax,[edi+0x2C]` 转成 VA 再判边界。

`shim_lsw` 采用"两段式"：先用原句柄调真函数，返回 0（`.rsrc` 里没有 `RT_STRING`）时
才换成预加载的 `<modpath 目录>\<lang>\<basename>.mui` 再调一次；`SysWOW64` 侧没有 MUI 时
把目录名等长替换成 `System32` 重试。

### 1.5 自适应：按 exe 决定要不要兼容层

兼容层（`b64_hooks` + 6 个 shim）占桩体约 **1.6 KB**，但只有一部分 exe 真的需要它。打包时按**导入表**判断：

```
COMPAT_IMPORTS = {GetModuleFileNameW, LoadStringW, FormatMessageW,
                  FindResourceW, FindResourceExW, LoadResource, SizeofResource}
```

命中任意一个 → 编入兼容层；一个都没有 → 汇编时加 `-DB64_NO_COMPAT`，把整段代码裁掉。

- 入口：`exe2shc.py --compat {auto,on,off}`（默认 `auto`）；打包输出里会打印「兼容层需要/不需要（已裁剪）」。
- 实测：`comreg.exe` 8,907 → **7,263 B**、`mimikatz.exe` 1,112,651 → **1,111,007 B**（各省 1,644 B）；`hostname/whoami/tasklist/ipconfig/systeminfo` 判定为需要，保持完整桩。
- 命中表实测：`hostname`(FormatMessageW)、`whoami`/`tasklist`/`systeminfo`(GetModuleFileNameW+LoadStringW+FormatMessageW)、`ipconfig`(FormatMessageW)、`comreg`/`mimikatz`/`fscan`(无)。

### 1.6 只有一条链路：压缩 + Z85（没有 raw）

`--raw` / `--mode` 已移除，x64 PE 一律「容器 + LZNT1 + Z85」，x86 PE 一律「loader_x86 包进 Z85」，
.NET 与裸 shellcode 同样先压缩再编码。省掉 raw 的代价是这类**已经压过**的样本产物会变大：

| 样本 | 原始 | 容器+Z85 产物 |
| --- | --- | --- |
| `fscan.exe`（Go + UPX） | 8,785,920 | 10,985,636 |
| `mimikatz.exe` | 1,250,056 | 1,041,736 |

换来的是：所有产物走同一套代码路径（命令行改写、兼容层、TLS/.pdata、MUI 回落都在），不再有
"raw 模式命令行不对、没有兼容层"这类分支差异。

## 1.7 编码层：Z85（2026-11 起 base64 全部替换）

载荷压缩后统一用 **Z85**（ZeroMQ 的 base85）编码，不再提供 base64 / none 选项。

- 字符集（85 个，按值域有序）：`0-9`(0–9) `a-z`(10–35) `A-Z`(36–61) 然后 `.-:+=^!/*?&<>()[]{}@%$#`(62–84)。
  不含引号、反斜杠与空白，产物可以安全放进源码字符串 / JSON / 配置文件而不转义。
- 分组：**4 字节 → 5 字符**，`v = ((((c0*85+c1)*85+c2)*85+c3)*85+c4)`，**大端**存回 4 字节（`bswap` 后 `mov [dst], eax`）。
- 输入长度不是 4 的倍数时补 `0` 字节到整组；解码端按头里的 `complen` 截断，所以
  **解出的字节数 = 4*ceil(complen/4) ≥ complen**——stub 里那句长度校验是 `jb .fail` 而不是 `jne .fail`。
- 解码表：桩里存 95 字节 `z85_tab`（索引 `ch-33`，覆盖 33..127，值 `0xFF` = 非法字符）；
  字符先 `sub eax,33 / cmp eax,95 / jae fail` 再做表查，非法字符直接放弃整条载荷。
- 体积：膨胀 1.250（base64 是 1.333）。本机实测：mimikatz 1,111,007 → **1,041,736**（−6.2%）、
  whoami 74,683 → **70,285**、tasklist 93,907 → **88,310**、comreg 7,263 → **6,976**。
- 桩成本：+约 150 B 代码与 95 B 表（x64 桩 4,355 → 4,350 B 是因为删掉了 base64 的位累加逻辑，净持平）。

## 2. stub 侧（stub/dec_b64_lznt1.asm）

`-DRUN_CONTAINER` 编出来的独立入口 `b64_run_start`：

```
b64_decode_payload        Z85 -> LZNT1 -> 容器字节
b64_build_image           VirtualAlloc(ImageBase, SizeOfImage, 0x3000, 0x40)
                          失败则 VirtualAlloc(NULL, ...)
                          逐节 memcpy(镜像+RVA, 容器+DataOff, RawSize) + XOR 解密
b64_reloc                 delta = 镜像 - ImageBase，遍历块表修 DIR64(10) / HIGHLOW(3)
b64_imports               LoadLibraryA(DLL 名) -> thunk 循环（序号/名字）-> 写 IAT
b64_fix_cmdline           把容器里存的命令行（或 "X.exe"）复制进 PEB 的 CommandLine 缓冲，
                          并把 Length/MaximumLength 改成实际长度、末尾补 2 字节 NUL
                          否则目标程序 argv[1] 会是宿主传进来的 .bin 路径
call 镜像 + EntryRVA      入口返回后 ExitProcess(0)
```

`ImagePathName` 仍然不动 —— 改它没意义（`GetModuleFileNameW` 不读它），真正补在 IAT 上，见下节。

### 1.2 路径兼容层（`b64_hooks`）

`whoami` / `tasklist` / `quser` / `where` 这类系统工具的身份链是：
`GetModuleFileNameW(NULL)` → `GetFileVersionInfoSizeExW(自己的路径)` →
`VerQueryValueW("\StringFileInfo\...\InternalName")` → `LoadStringW(NULL, id)` 去加载
`<同目录>\<语言>\<自己>.mui`。它们在内存里运行时前两步全错，最后只能报
`The specified resource type cannot be found in the image file.`。

容器因此额外携带原始 exe 路径（`ModPath` 块），`b64_hooks` 在跳入口前做两件事：

1. 遍历目标镜像的 `IMAGE_IMPORT_DESCRIPTOR`（`FirstThunk`，即 IAT，步长 0x14），
   把等于 `kernel32!GetModuleFileNameW` 的槽换成 `b64_shim_gmfn`：
   `hModule == NULL` 时返回容器里的原始路径（按调用方 `nSize` 截断并补 NUL），
   其它情况原样转发给真函数。
2. 把等于 `user32!LoadStringW` / `kernelbase!LoadStringW` 的槽换成 `b64_shim_lsw`：
   先按原句柄调真函数；**返回 0**（说明目标 `.rsrc` 里没有 `RT_STRING`）才调
   `b64_mui_get` 换 MUI 句柄重试一次。

`b64_mui_get` **不拼字符串**：MUI 候选路径是**打包时**算好写进容器的
（`<dir>\zh-CN\<name>.mui`、`<dir>\en-US\<name>.mui`），运行时只是依次
`LoadLibraryExW(path, 0, LOAD_LIBRARY_AS_DATAFILE)`，成功即缓存。
早期版本在桩里用宽字符拼路径，`build_path`/`wcopy` 这条链在 x64 下始终拼不对
（`tasklist` 表头一直空），改成打包期生成后再没出问题 —— **运行时不拼宽串**是本层的硬约束。

两条硬约束：

- **只在 user32 已加载时挂钩**（`GetModuleHandleA("user32.dll")`）。这里刻意不调
  `LoadLibraryA`：`b64_tls` 之后再去加载新的 DLL，会让 loader 在装新模块的 TLS 时踩到
  我们刚接管的 TEB 槽（实测 Rust 样本必崩 0xC0000005）。目标程序自己静态导入 user32 的
  情况（whoami/she113 之流）在 `b64_imports` 阶段就加载好了，没有问题。
- 路径来自容器，所以程序在**打包机上**的路径在目标机上不存在时，版本信息/MUI 依然会失败
  —— 这是"带原路径"方案的固有代价，属正常降级（退回原来的报错）。

不定义 `RUN_CONTAINER` 时这些函数也在，可以在自己的 loader 里 `call b64_load_and_run`。

## 3. 打包

```bash
# 默认就是容器模式（不加密，只有 Z85 + LZNT1）
python tools/pack_b64_lznt1.py --payload target.exe --out run.bin
.\runshc64.exe run.bin

# 关掉容器层：解压出来是原始 PE，交给 loader_x64.asm
python tools/pack_b64_lznt1.py --payload target.exe --out run.bin --no-container

# 确实需要节数据 XOR 时才显式开
python tools/pack_b64_lznt1.py --payload target.exe --out run.bin --key-len 11

# 只校验 Z85+LZNT1 往返（退出码 0 = 解出的容器字节与打包端一致）
python tools/pack_b64_lznt1.py --payload target.exe --out t.bin --test
```

产物：`[RUN_CONTAINER stub][数据块 0x14 头][Z85 文本]`。

模式选择规则：不给 `--asm` → 容器模式；给了 `--asm`（例如 `build/loader_b64_demo.asm`）→ 自动回落裸 PE 模式，
因为 loader 副本走的是标准 PE 流程。裸 PE 模式必须给 `--cmdline` / `--image-path` 生成实例参数块，
否则 loader 会把 CommandLine 设成空、目标程序 argv 全空（comreg 就不打用法了）；容器模式不用给，
它在运行时改 PEB 的 CommandLine。

## 4. 实测

运行验证（`runshc64.exe`，64 位进程内起线程）：

| 载荷 | 容器模式 | 原 loader 基线 |
|---|---|---|
| comreg.exe | 打印同样用法文本，退出码 2 | 打印同样用法文本，退出码 2 |
| hostname.exe | 输出 `Lenovo` | 无输出 |
| mimikatz.exe | 完整 banner + `mimikatz(commandline) #` 提示符 | — |
| mimikatz.exe --args "exit" | `mimikatz(commandline) # exit` + `Bye!` | — |
| comreg.exe --args "-u {CLSID}" | `[-] 已卸载 {CLSID}` | 同左 |
| comreg.exe（无参数） | 打印用法三行，退出码 2 | 同左 |
| comreg.exe --key-len 0 | 打印同样用法文本，退出码 2 | — |
| comreg.exe --test | 退出码 0（FNV-1a64 一致） | — |
| ipconfig.exe | 完整输出（`Windows IP 配置` + 各适配器） | 静默 |
| route.exe / netstat.exe | 输出表头与内容 | 静默 |
|                                |                                                |                            |

体积（容器 vs 原始 PE 直接压缩，LZNT1 后字节数）：

| 载荷 | 原 PE | 容器大小 | LZNT(原 PE) | LZNT(容器, 无钥) | LZNT(容器, 11B 钥) |
|---|---|---|---|---|---|
| comreg.exe | 5,632 | 3,913 / 3,924 | 3,242 | 2,843 | 3,752 |
| whoami.exe | 98,304 | 81,456 / 81,467 | 53,336 | 51,738 | 68,758 |
| mimikatz.exe | 1,250,056 | 1,236,018 / 1,236,029 | 839,693 | 830,405 | 1,101,357 |

结论：**不加密时容器稳定变小**（省掉头和填充）；**加密会把压缩率打掉**
（mimikatz 830K → 1101K，+33%），这是样本那种做法的固有代价——XOR 之后的节数据基本不可压缩。
所以默认 `--key-len 0`，只在确实要混淆时才加密。

最终产物（stub + 头 + Z85 文本）大小，容器无钥 vs 裸 PE 直压：

| 载荷 | 原 PE | 容器模式 bin | 裸 PE 模式 bin | 差 |
|---|---|---|---|---|
| comreg.exe | 5,632 | 5,516 | 5,968 | -7.6% |
| hostname.exe | 40,960 | 12,752 | 15,764 | -19.1% |
| mimikatz.exe | 1,250,056 | 1,108,932 | 1,121,236 | -1.1% |

### 1.4 文案取自 RT_MESSAGETABLE 的程序（ipconfig / route / netstat）

这类程序不用 MUI，而是 `FormatMessageW(0x900, GetModuleHandleW(NULL), id, ...)`：
`0x800` = FROM_HMODULE、`0x100` = ALLOCATE_BUFFER，文案在**自身 `.rsrc` 的 RT_MESSAGETABLE** 里。

容器模式把镜像私有映射到内存，`GetModuleHandleW(NULL)` 被我们改成返回这个镜像（PEB.ImageBaseAddress），
真函数拿它去 Ldr 里找模块 → 找不到 → 返回 0（文案全空，程序静默）或直接 AV。修法是三步：

1. **打包时**把原始 exe 全路径（ModPath）连同末尾 NUL 一起塞进容器；
2. 桩里 `b64_shim_fmt` 挂在 IAT 的 `FormatMessageW` 上：`lpSource == 自建镜像` 时换用
   `LoadLibraryExW(<ModPath>, 0, LOAD_LIBRARY_AS_DATAFILE)` 的句柄（`b64_dfile_get` 缓存），再调真函数；
3. `FormatMessageW` 是 7 参数（5 个进寄存器、`lpBuffer`/`nSize`/`Arguments` 在栈上），**shim 里重新 call
   真函数前必须把调用方的 3 个栈参数复制进自己的帧**——否则新帧低于原 `rsp`，被调方按 `[rsp+0x28]`
   取到的是垃圾，表现是系统 DLL 内部 `0xc0000005`。

注意 x64 的 `lpSource` 是寄存器传参，栈参数却要按上面的偏移复制；x86 用同一个套路改成
就地改 `[esp+8]` 再尾跳。**ModPath 末尾那个 NUL 不能省**——`LoadLibraryExW` 按 C 宽串读，
少了它会读进后面的 MUI 块，返回 0。

## 5. 限制

- 依赖「自身文件路径」的程序（`whoami.exe` / `tasklist.exe` / `where.exe` 等）在 **x64 容器模式**
  下已修好（见 1.2 路径兼容层）；**x86 包装模式**在 `loader_x86.asm` 里做了同一层：`shim_gmfn` / `shim_lsw` + `SysWOW64→System32` 等长替换，另外把 kernelbase 的 `GetCommandLineW/A` 缓存（WOW64 下是 `a1 imm32 c3` 的绝对地址）在**解析导入之前**就地改写，并用 `pushad/popad` 包住，否则 msvcrt 系目标（whoami/tasklist）会把宿主 `runshc32.exe` 的命令行当成自己的 argv。
  `.rsrc` 是普通节，容器会照原样拷进去（实测自编 STRINGTABLE 程序在容器模式下
  `LoadStringW(NULL,1)` 返回 `RS-OK`），所以问题不在资源本体，而在路径：
  `GetModuleFileNameW(NULL)` 取的是 kernelbase 启动时缓存的**宿主** exe 路径
  （改 `PEB->Ldr`、改 `ProcessParameters.ImagePathName` 都不生效，本机 19045 实测），
  于是 `GetFileVersionInfoSizeExW(宿主路径)` → `VerQueryValueW("\StringFileInfo\...\InternalName")`
  → `LoadStringW(NULL, id)` 转去找 MUI 文件 → `ERROR_MUI_FILE_NOT_FOUND (15105)`
  → 最终报 `The specified resource type cannot be found in the image file.`。
  Windows 自带这些工具的文案本来就不在 exe 里，而在 `System32\en-US\*.exe.mui`。
- `.pdata` 会注册给系统（`RtlAddFunctionTable`），但只覆盖我们这一个镜像；宿主自己的异常链不受影响。
- TLS 已支持（索引/模板/TEB 槽/回调），但只在**当前线程**上建立；
  目标程序若自己起新线程，那线程的 TLS 槽取决于系统 loader，不属于本桩职责。
- 目标程序如果直接解析自身 PE 头（mingw CRT、部分加壳器），容器里那份头的 `FileAlignment` 相关字段
  仍是原文件的值，只有 `[0, SizeOfHeaders)` 这段被回写；`SizeOfImage` / 节表等都在，够用。
- 无重定位表的 PE 只能落在首选基址，`VirtualAlloc(ImageBase)` 失败就崩（和原 loader 同样限制）。

## 6. 非 PE 输入（裸 shellcode）

`exe2shc.py` 看到输入前两个字节不是 `MZ` 时，自动切到 `-DRUN_RAW` 桩：

```
Z85 解码 -> LZNT1 解压 -> call 解压缓冲
```

解压缓冲本身就是 `PAGE_EXECUTE_READWRITE`，不用再改保护；shellcode 自己返回就 `ExitProcess(0)`，
Z85/解压失败就 `ExitProcess(1)`。

```bash
python exe2shc.py payload.bin out.bin      # 任意 x64 位置无关 shellcode
.
unshc64.exe out.bin
```

实测：`build/sc_r.bin`（单字节 `c3`）→ 退出码 0；`build/sc_int3.bin`（单字节 `cc`）→ 退出码 3
（确实 call 进去了）；把产物里一个 Z85 字符改坏 → 退出码 1。

限制：

- 只支持 x64；x86 shellcode 会被当数据压进去，跑不起来。
- 不给 shellcode 传任何参数（按「无参、位置无关」处理）。
- msfvenom 那类开头就 `and rsp,-16` 的 shellcode 会丢掉 `call` 的返回地址，必须自己结束进程
  （`ExitProcess` / 死循环），别指望 `ret` 回来——这是 shellcode 的通用约定，跟本桩无关。

### 示例：弹窗 shellcode

`build/popup_sc.asm` 是一段 173 字节的位置无关 x64 shellcode：从 PEB 拿 kernel32 →
解析导出表按 djb2 哈希找 `WinExec` → `WinExec(CMD, SW_SHOW)`。改最后一行
`cmd: db "notepad.exe", 0` 就能起任意程序。

```bash
tools\nasm-2.16.03\nasm.exe -f bin -o build\popup_ctl.bin build\popup_ctl.asm
python exe2shc.py build\popup_ctl.bin .\popup.bin
.\runshc64.exe .\popup.bin          # 弹出「控制面板」窗口
```

实测：载荷 193 B → 压缩 207 B → Z85 260 B，产物约 2,0xx B，退出码 0，
`control.exe` 进程正常出现在 Console 会话。

注意 Win11 上 `calc.exe` / `notepad.exe` 都是 Store 应用，`WinExec` 能返回成功但窗口激活不起来
（这是 UWP 激活模型的限制，不是 shellcode 或本桩的问题）；用 `control.exe`、`mspaint.exe`
这类传统 Win32 程序验证最直接。

## 7. 32 位（x86）自解压桩

`stub/dec_b64_lznt1_x86.asm` 是 32 位版本（BITS 32，入口即偏移 0，汇编后 636 字节），
能力和 x64 桩对齐：Z85 → LZNT1 → 解压后直接 `call`。

- 取基准：`call b64_getpc / b64_getpc: pop ebx`（x86 没有 RIP 相对，只能这么拿 EIP）。
- PEB：`fs:[0x30]` → `Ldr`(+0x0C) → `InMemoryOrderModuleList`(+0x14) → 两次解引用得 kernel32，
  `[eax+0x10]` = DllBase。
- 用 djb2 解析：`GetProcAddress` / `LoadLibraryA` / `VirtualAlloc` / `ExitProcess`，
  再 `LoadLibraryA("ntdll.dll")` + `GetProcAddress("RtlDecompressBuffer")`。
- 局部变量放在 `[esp+0x00] .. [esp+0x28]`（`sub esp,0x40` 预留）。

**踩坑**：`GetProcAddress` / `LoadLibraryA` / `VirtualAlloc` / `RtlDecompressBuffer` / `ExitProcess`
在 32 位下都是 stdcall、自己清栈。如果按 cdecl 习惯在每个 `call` 后面补 `add esp,4/8/16/24`，
栈会被多弹 4 字节（32 位下 `push eax; call` 只压 4 字节返回地址），局部变量全部错位，
表现是 `0xC0000005`。正确写法：**什么都不加**。

## 8. 四种输入现在都走 Z85 + LZNT1

| 输入 | 走的链路 | 产物布局 |
| --- | --- | --- |
| x64 PE（PE32+） | 容器层 + Z85 + LZNT1 | `x64 桩 + 头 + Z85(容器)` |
| x86 PE（PE32） | Z85 + LZNT1 包住 `loader_x86 + 实例块 + 原始 PE` | `x86 桩 + 头 + Z85(载荷)` |
| .NET 程序集 | Z85 + LZNT1 包住 `CLR bootstrap + 启动器程序集`（启动器内嵌原程序集） | 按架构选 x64/x86 桩；参数由启动器反射传入 |
| 任意 shellcode（非 MZ） | Z85 + LZNT1，解压后直接 `call` | 按架构选桩（`--arch auto` 自动识别） |

常用命令：

```bash
python exe2shc.py app.exe     out.bin          # x64 PE → 容器模式（默认）
python exe2shc.py app32.exe   out.bin          # x86 PE → x86 自解压桩
python exe2shc.py managed.exe out.bin          # .NET  → 桩 + CLR bootstrap
python exe2shc.py sc.bin      out.bin          # shellcode，自动识别架构
python exe2shc.py sc32.bin    out.bin --arch x86
```

体积对比（本机实测）：x86 `where.exe` 35,164 → 34,144 字节；.NET 64 位 hello 5,435 字节
载荷 → 压缩 3,134 → 产物 5,980 字节（解压内容与载荷逐字节一致）。

已知限制：CLR bootstrap（`stub/clr/clr_x64.bin` / `clr_x86.bin`）调目标 `Main` 时只能安全地
传 `null` —— 它构造的参数数组是 `SAFEARRAY(VT_VARIANT)`，里面那个元素从未初始化。实测把元素
改成真实数组（`VT_ARRAY|VT_BSTR` 或 `VT_ARRAY|VT_VARIANT`，0 元素与 1 元素都试过）会让 CLR 在
「变体 → 托管数组」的转换里空指针崩溃（`rip=0`，入口一次都没进去），改成 `VT_BSTR`(null) 只等于
「没有参数」。所以 .NET 的参数改为由托管启动器传，见第 9 节。

## 9. .NET 参数：默认走托管启动器

做法（`exe2shc.py::build_launcher`，默认开启）：

1. 生成 `Launcher.cs`，把目标程序集字节作为 `byte[]` 字面量内嵌；
2. `csc /nologo /target:exe /platform:x64|x86` 编成启动器程序集；
3. 启动器运行时 `Assembly.Load(payload)` → `EntryPoint.Invoke`，参数按
   `entry.GetParameters().Length` 判断：无参方法传 `null`，`Main(string[])` 传
   `new string[0]`（没有命令行时）或 `new string[]{ cmd }`；
4. 启动器本身仍走「Z85 + LZNT1 + CLR bootstrap」，压缩链路不变。

参数来源：宿主进程 `Environment.GetCommandLineArgs()` 的 `cl[2..]` 优先，为空时用 `--args`
在生成时嵌入的默认值。

- `--no-launcher`：退回旧行为（bootstrap 直嵌程序集，目标 `Main` 收到 `null`）；
- `csc.exe` 不可用时自动回退并打印提示。

实测（`runshc64.exe` / `runshc32.exe`）：

| 目标 | 产物 | 输出 |
| --- | --- | --- |
| `hello6.exe`（`Main()`） | `build/l6.bin`（8,988 B） | `NOARGS-OK` |
| `hello7.exe`（`Main(string[])`，不带参数） | `build/l7b.bin`（9,176 B） | `REACHED-ENTRY` / `ARGS-LEN=0` |
| `hello7.exe --args "alpha beta"` | `build/l7.bin`（9,256 B） | `ARGS-LEN=1` |
| `hello32.exe`（x86，`--args "one two"`） | `build/l32.bin`（7,896 B） | `hello from .NET, args=one two` |

体积代价：启动器本身是 3–4 KB 量级的托管程序集，加上 `byte[]` 字面量（每字节约 6 个字符），
内嵌后比直接嵌程序集大约 6 倍源码体积，压缩后影响不大（示例 3,584 B 程序集 → 启动器 7,680 B
→ 压缩 3,134 B 量级）。

---

## 10. 回归矩阵（`build/mx/matrix.py`）

一份跑得动的对照表，覆盖 x64 / x86 / .NET / Go / Rust / TLS / C++ 异常。做法：每个样本先跑原生拿
基线退出码，再 `exe2shc.py` 打包（容器 / 包装，无 raw），用 `runshc64/32.exe` 跑，
比对「退出码 + 关键字」。

| 用例 | 架构/运行时 | 模式 | 退出码 | 结果 |
| --- | --- | --- | --- | --- |
| C hello（`printf` + `argc/argv` + `return 7`） | x64 C | 容器 | 7 = 原生 | ✓ `argc=3` |
| 命令行三源探针（PEB / `GetCommandLineA/W` / `argv`） | x64 C | 容器 | 0 | ✓ 三源一致 |
| 带引号参数 `'"x y" z'` | x64 C | 容器 | 7 | ✓ `arg[1]=x y` |
| C++ `std::runtime_error` 抛捕获 | x64 C++ | 容器 | 0 | ✓ 需 `.pdata` 注册 |
| `__thread` + `.CRT$XLB` TLS 回调 | x64 C | 容器 | 0 | ✓ `TLS-CB attach` / `TLS-VAR 1235` |
| Go 1.25 `os.Args` + `os.Exit(5)` | x64 Go | 容器 | 5 = 原生 | ✓ `args=2` |
| Rust 1.98 `env::args` + `exit(6)` | x64 Rust | 容器 | 6 = 原生 | ✓ `args=2` |
| comreg.exe（`-u {CLSID}`） | x64 原生 | 容器 | 0 | ✓ `[-] 已卸载 {…}` |
| hostname.exe | x64 原生 | 容器 | 0 | ✓ `Lenovo` |
| mimikatz.exe（`--args exit`） | x64 原生 | 容器 | 0 | ✓ banner + `Bye!` |
| Go `os.Args` + exit(5) | x86 Go | 包装 | 5 = 原生 | ✓ `args=2` |
| 命令行探针 | x86 Go | 包装 | 0 | ✓ `W=[go_probe32.exe p q]` |
| where.exe（SySWOW64） | x86 原生 | 包装 | 2 = 原生 | ✓ 资源限制照旧 |
| C# `Main(string[])` 返回 4 | .NET AnyCPU / x64 | 启动器 + 容器 | 4 = 原生 | ✓ `bits=64` |
| C# 同上 | .NET x86 | 启动器 + x86 桩 | 4 = 原生 | ✓ `bits=32` |

要点：

- **x86 命令行**：`loader_x86.asm` 除了改 PEB32，还会定位 `kernelbase!GetCommandLineW`，若其实现是
  `mov eax,[imm32]; ret`（Win10/11 都这样）就把缓存变量指向我们的串——WOW64 下只改 PEB 不够；
- **x64 命令行**：容器桩改完 PEB 再同步 `kernelbase!GetCommandLineA` 的 ANSI 缓存（mingw CRT 的
  `argv` 从这里取）；
- **.NET 退出码**：启动器把 `EntryPoint.Invoke` 的 `int` 返回值用 `Environment.Exit` 透传，和原生一致。

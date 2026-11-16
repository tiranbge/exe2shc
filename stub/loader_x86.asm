; ============================================================================
; loader_x86.asm  ——  x86 "run PE from memory" 加载桩（位置无关）
;
; 编译：  nasm -f bin -o loader_x86.bin loader_x86.asm
;
; 运行时布局与实例参数块结构同 loader_x64.asm（见 README）。
; 流程完全镜像 x64 版本，仅寄存器/结构偏移按 32 位调整。
; ============================================================================

BITS 32

; djb2 哈希常量
HASH_GETPROCADDRESS equ 0xcf31bb1f
HASH_LOADLIBRARYA   equ 0x5fbff0fb
HASH_VIRTUALALLOC   equ 0x382c0f97

    ; 入口：find_export 在文件前部，必须保证偏移 0 处是真正入口
    jmp   start

; ---------------------------------------------------------------------------
; find_export:
;   输入: edx = 模块基址, ecx = 目标导出名 djb2 哈希
;   输出: eax = 函数地址（失败为 0）
; ---------------------------------------------------------------------------
find_export:
    push ebx
    push esi
    push edi
    push ebp
    sub  esp, 0x10

    mov  esi, edx                 ; module base
    mov  ebp, ecx                 ; target hash

    mov  eax, [esi + 0x3C]        ; e_lfanew
    add  eax, esi                 ; PE header
    mov  eax, [eax + 0x78]        ; export RVA (PE32 DataDirectory[0])
    test eax, eax
    jz   .notfound
    add  eax, esi                 ; export dir
    mov  edi, eax

    mov  eax, [edi + 0x18]
    mov  [esp + 0x00], eax        ; NumberOfNames
    mov  eax, [edi + 0x20]
    mov  [esp + 0x04], eax        ; AddressOfNames RVA
    mov  eax, [edi + 0x1C]
    mov  [esp + 0x08], eax        ; AddressOfFunctions RVA
    mov  eax, [edi + 0x24]
    mov  [esp + 0x0C], eax        ; AddressOfNameOrdinals RVA

    xor  edx, edx                 ; i = 0
.loop:
    cmp  edx, [esp + 0x00]
    jae  .notfound
    mov  eax, [esp + 0x04]
    add  eax, esi
    mov  eax, [eax + edx*4]       ; name RVA
    add  eax, esi                 ; name ptr

    mov  ecx, 5381                ; djb2 hash 累积
.hash:
    movzx ebx, byte [eax]
    test  ebx, ebx
    jz    .cmp
    imul  ecx, ecx, 33
    add   ecx, ebx
    inc   eax
    jmp   .hash
.cmp:
    cmp   ecx, ebp
    je    .found
    inc   edx
    jmp   .loop

.found:
    mov   eax, [esp + 0x0C]       ; ordinals RVA
    add   eax, esi
    movzx eax, word [eax + edx*2] ; ordinal
    mov   ecx, [esp + 0x08]       ; functions RVA
    add   ecx, esi
    mov   eax, [ecx + eax*4]      ; function RVA
    add   eax, esi
    jmp   .done

.notfound:
    xor   eax, eax
.done:
    add   esp, 0x10
    pop   ebp
    pop   edi
    pop   esi
    pop   ebx
    ret

; ---------------------------------------------------------------------------
; 入口
; ---------------------------------------------------------------------------
start:
    ; ==== 0. 忽略运行时参数：x86 包装模式统一用实例块里的命令行 ====
    ; （runtime 参数是宿主 runshc32.exe 的命令行，目标程序会把它当成自己的 argv）
    xor  esi, esi

    ; ==== 1. 定位实例参数块 ====
    call lbl
lbl:
    pop  ebx
    add  ebx, args_block - lbl

    ; ==== 2. 读取长度字段 ====
    movzx eax, word [ebx + 0]     ; cmdlineLen
    movzx ecx, word [ebx + 2]     ; imagePathLen

    ; ==== 3. 重建 ProcessParameters（CommandLine + ImagePathName） ====
    mov   edx, [fs:0x30]          ; PEB
    mov   edx, [edx + 0x10]       ; ProcessParameters

    ; CommandLine：优先运行时参数，否则回退到嵌入块
    test  esi, esi
    jz    .use_embedded_cmd
    mov   edi, esi
.cmdlen_loop:
    cmp   word [edi], 0
    je    .cmdlen_done
    add   edi, 2
    jmp   .cmdlen_loop
.cmdlen_done:
    sub   edi, esi
    jz    .use_embedded_cmd
    mov   [edx + 0x44], esi       ; Buffer
    mov   [edx + 0x40], di        ; Length
    mov   [edx + 0x42], di        ; MaximumLength
    jmp   .cmd_done
.use_embedded_cmd:
    test  eax, eax
    jz    .cmd_done
    lea   esi, [ebx + 4]
    mov   [edx + 0x44], esi
    mov   [edx + 0x40], ax
    mov   [edx + 0x42], ax
.cmd_done:

    ; ImagePathName (x86 偏移: Length 0x38, MaxLength 0x3A, Buffer 0x3C)
    test  ecx, ecx
    jz    .no_imagepath
    lea   esi, [ebx + eax + 6]    ; ImagePathName 数据 = 4 + cmdlineLen + 2
    mov   [edx + 0x3C], esi       ; Buffer
    mov   [edx + 0x38], cx        ; Length
    mov   [edx + 0x3A], cx        ; MaximumLength
.no_imagepath:

    ; ==== 4. 定位嵌入 EXE ====
    ; exe = 参数块 + 4 + cmdlineLen + 2 + imagePathLen + 2
    lea   esi, [ebx + eax + 8]
    add   esi, ecx

    ; ==== 4. 找 kernel32.dll 基址 ====
    mov   eax, [fs:0x30]          ; PEB
    mov   eax, [eax + 0x0C]       ; Ldr
    mov   eax, [eax + 0x14]       ; InMemoryOrderModuleList.Flink
    mov   eax, [eax]              ; 第 2 个模块
    mov   eax, [eax]              ; 第 3 个模块 (kernel32)
    mov   ebp, [eax + 0x10]       ; DllBase

    ; ==== 5. 栈帧 + 解析 API ====
    sub   esp, 0x54
    mov   edi, esp                ; 保存区基址（此后用 [edi+偏移] 访问）

    mov   edx, ebp
    mov   ecx, HASH_GETPROCADDRESS
    call  find_export
    test  eax, eax
    jz    fail_late
    mov   [edi + 0x00], eax       ; GetProcAddress

    mov   edx, ebp
    mov   ecx, HASH_LOADLIBRARYA
    call  find_export
    test  eax, eax
    jz    fail_late
    mov   [edi + 0x04], eax       ; LoadLibraryA

    mov   edx, ebp
    mov   ecx, HASH_VIRTUALALLOC
    call  find_export
    test  eax, eax
    jz    fail_late
    mov   [edi + 0x08], eax       ; VirtualAlloc


    pushad
    ; ==== 5.5 同步 kernelbase 的 GetCommandLineW 缓存 ====
    ; WOW64 下只改 PEB32 的 CommandLine 还不够：kernelbase32 的 GetCommandLineW
    ; 可能实现成 mov eax,[缓存变量]; ret（Win11 就是），目标程序仍读旧值。
    ; 这里定位该函数，若首字节是 A1（mov eax, [imm32]）就把缓存变量改成我们的串。
    call  .kb_pc
.kb_pc:
    pop   ebx
    lea   eax, [ebx + str_kb - .kb_pc]
    push  eax
    call  dword [edi + 0x04]            ; LoadLibraryA("kernelbase.dll")
    test  eax, eax
    jz    .kb_done
    lea   edx, [ebx + str_gclw - .kb_pc]
    push  edx
    push  eax
    call  dword [edi + 0x00]            ; GetProcAddress(hmod, "GetCommandLineW")
    test  eax, eax
    jz    .kb_done
    cmp   byte [eax], 0xA1              ; mov eax, dword ptr [imm32] ?
    jne   .kb_done
    mov   edx, [eax + 1]                ; A1 后面是缓存变量的**绝对地址**（加载时已重定位）
    test  edx, edx
    jz    .kb_done
    cmp   edx, 0x10000
    jb    .kb_done
    mov   ecx, [fs:0x30]
    mov   ecx, [ecx + 0x10]
    mov   ecx, [ecx + 0x44]             ; 新的 CommandLine 缓冲
    test  ecx, ecx
    jz    .kb_done
    mov   [edx], ecx
.kb_done:

    ; ==== 5.6 就地改写 ANSI 命令行缓存（msvcrt 系目标从这里取 argv） ====
    push  ebp
    push  edi
    call  .ga_pc
.ga_pc:
    pop   ebx
    lea   eax, [ebx + str_kb - .ga_pc]
    push  eax
    call  dword [edi + 0x04]            ; LoadLibraryA("kernelbase.dll")
    test  eax, eax
    jz    .ga_done
    mov   esi, eax
    lea   edx, [ebx + str_gcla - .ga_pc]
    push  edx
    push  esi
    call  dword [edi + 0x00]            ; GetProcAddress("GetCommandLineA")
    test  eax, eax
    jz    .ga_done
    call  eax                           ; 现有 ANSI 串
    test  eax, eax
    jz    .ga_done
    mov   ebp, eax                      ; 目标缓冲

    mov   ecx, [fs:0x30]
    mov   ecx, [ecx + 0x10]
    mov   esi, [ecx + 0x44]             ; 新的宽 CommandLine
    test  esi, esi
    jz    .ga_done
    lea   edi, [ebx + ansi_buf - .ga_pc]
    mov   edx, edi
.ga_cp:
    mov   ax, [esi]
    test  ax, ax
    jz    .ga_cp_done
    cmp   ax, 0x7F
    ja    .ga_done
    mov   [edi], al
    add   esi, 2
    inc   edi
    mov   ecx, edi
    sub   ecx, edx
    cmp   ecx, 0x100
    jb    .ga_cp
    jmp   .ga_done
.ga_cp_done:
    mov   byte [edi], 0

    xor   ecx, ecx
.ga_len:
    cmp   byte [ebp + ecx], 0
    je    .ga_len_done
    inc   ecx
    cmp   ecx, 0x800
    jb    .ga_len
    jmp   .ga_done
.ga_len_done:
    mov   eax, edi
    sub   eax, edx                      ; 我们的长度
    cmp   eax, ecx
    ja    .ga_done
    mov   esi, edx
    mov   edi, ebp
    inc   eax
    mov   ecx, eax
    rep   movsb
.ga_done:
    pop   edi
    pop   ebp

    popad
    ; ==== 6. 解析嵌入 EXE 的 PE 头 ====
    cmp   word [esi], 0x5A4D
    jne   fail_late
    mov   eax, [esi + 0x3C]
    add   eax, esi                ; PE header
    cmp   dword [eax], 0x00004550
    jne   fail_late

    movzx ecx, word [eax + 6]     ; NumberOfSections
    movzx edx, word [eax + 20]    ; SizeOfOptionalHeader
    add   eax, 24                 ; optional header
    lea   ebx, [eax + edx]        ; section table 起点

    mov   [edi + 0x0C], esi       ; exe base
    mov   [edi + 0x10], ebx       ; section table
    mov   [edi + 0x14], ecx       ; NumberOfSections
    mov   ebx, [eax + 0x38]
    mov   [edi + 0x18], ebx       ; SizeOfImage
    mov   ebx, [eax + 0x3C]
    mov   [edi + 0x1C], ebx       ; SizeOfHeaders
    mov   ebx, [eax + 0x10]
    mov   [edi + 0x20], ebx       ; EntryPoint
    mov   ebx, [eax + 0x1C]
    mov   [edi + 0x24], ebx       ; ImageBase
    mov   [edi + 0x28], eax       ; optional header

    ; ==== 7. 分配内存 ====
    push  0x40                    ; PAGE_EXECUTE_READWRITE
    push  0x3000                  ; MEM_COMMIT | MEM_RESERVE
    push  dword [edi + 0x18]      ; dwSize = SizeOfImage
    push  0                       ; lpAddress = NULL
    call  dword [edi + 0x08]      ; VirtualAlloc（stdcall，自动清 16 字节）
    test  eax, eax
    jz    fail_late
    mov   [edi + 0x2C], eax       ; base

    ; ==== 8. 拷贝 headers ====
    mov   ecx, [edi + 0x1C]
    mov   esi, [edi + 0x0C]
    push  edi
    mov   edi, [edi + 0x2C]
    rep movsb
    pop   edi

    ; ==== 9. 拷贝 sections ====
    mov   eax, [edi + 0x10]
    mov   ecx, [edi + 0x14]
.copy_sec:
    test  ecx, ecx
    jz    .copy_done
    mov   edx, [eax + 12]         ; VirtualAddress
    mov   ebx, [eax + 16]         ; SizeOfRawData
    test  ebx, ebx
    jz    .next_sec
    push  ecx
    push  eax
    push  edi
    mov   esi, [edi + 0x0C]
    add   esi, [eax + 20]         ; src = exe + PointerToRawData
    mov   edi, [edi + 0x2C]
    add   edi, edx                ; dst = base + VirtualAddress
    mov   ecx, ebx
    rep movsb
    pop   edi
    pop   eax
    pop   ecx
.next_sec:
    add   eax, 40
    dec   ecx
    jmp   .copy_sec
.copy_done:

    ; ==== 10. 基址重定位 ====
    mov   eax, [edi + 0x2C]
    sub   eax, [edi + 0x24]
    jz    .reloc_done
    mov   [edi + 0x30], eax       ; delta
    mov   eax, [edi + 0x28]       ; optional header
    mov   ebx, [eax + 0x88]       ; reloc VA (PE32 DataDirectory[5])
    mov   ecx, [eax + 0x8C]       ; reloc size
    test  ebx, ebx
    jz    .reloc_done
    add   ebx, [edi + 0x2C]       ; blk ptr
    add   ecx, ebx
    mov   [edi + 0x38], ecx       ; end
.reloc_blk:
    cmp   ebx, [edi + 0x38]
    jae   .reloc_done
    mov   eax, [ebx + 0]
    mov   [edi + 0x34], eax       ; page RVA
    mov   esi, [ebx + 4]          ; block size
    lea   esi, [ebx + esi]        ; block end
    lea   eax, [ebx + 8]          ; 条目指针
.reloc_ent:
    cmp   eax, esi
    jae   .reloc_next_blk
    mov   edx, [eax]
    movzx edx, dx
    mov   ecx, edx
    shr   ecx, 12                 ; type
    and   edx, 0xFFF              ; offset
    cmp   ecx, 3                  ; IMAGE_REL_BASED_HIGHLOW
    jne   .reloc_ent_next
    mov   ecx, [edi + 0x2C]       ; base
    add   ecx, [edi + 0x34]       ; + page RVA
    add   ecx, edx                ; + offset
    mov   edx, [edi + 0x30]       ; delta
    add   dword [ecx], edx
.reloc_ent_next:
    add   eax, 2
    jmp   .reloc_ent
.reloc_next_blk:
    mov   ebx, esi
    jmp   .reloc_blk
.reloc_done:

    ; ==== 11. 导入表修复 ====
    mov   eax, [edi + 0x28]       ; optional header
    mov   ebx, [eax + 0x68]       ; import VA (PE32 DataDirectory[1])
    test  ebx, ebx
    jz    .imp_done
    add   ebx, [edi + 0x2C]       ; desc ptr
.imp_dll:
    cmp   dword [ebx + 0], 0
    jne   .imp_has
    cmp   dword [ebx + 16], 0
    je    .imp_done
.imp_has:
    mov   eax, [ebx + 12]         ; name RVA
    add   eax, [edi + 0x2C]
    push  eax
    call  dword [edi + 0x04]      ; LoadLibraryA
    test  eax, eax
    jz    .imp_next_dll
    mov   [edi + 0x3C], eax       ; dll handle

    mov   eax, [ebx + 0]          ; OriginalFirstThunk
    test  eax, eax
    jnz   .imp_use_oft
    mov   eax, [ebx + 16]
.imp_use_oft:
    add   eax, [edi + 0x2C]
    mov   [edi + 0x40], eax       ; thunk 数组地址
    mov   eax, [ebx + 16]
    add   eax, [edi + 0x2C]
    mov   [edi + 0x44], eax       ; IAT 写回地址
.imp_thunk:
    mov   eax, [edi + 0x40]
    mov   eax, [eax]              ; thunk 值
    test  eax, eax
    jz    .imp_next_dll
    mov   edx, eax
    and   edx, 0x80000000
    jnz   .imp_ord
    add   eax, [edi + 0x2C]       ; IMAGE_IMPORT_BY_NAME
    add   eax, 2                  ; 跳过 Hint
    push  eax
    push  dword [edi + 0x3C]      ; hModule
    call  dword [edi + 0x00]      ; GetProcAddress
    jmp   .imp_store
.imp_ord:
    and   eax, 0xFFFF
    push  eax
    push  dword [edi + 0x3C]
    call  dword [edi + 0x00]
.imp_store:
    mov   edx, [edi + 0x44]
    mov   [edx], eax
    mov   edx, [edi + 0x40]
    add   edx, 4
    mov   [edi + 0x40], edx
    mov   edx, [edi + 0x44]
    add   edx, 4
    mov   [edi + 0x44], edx
    jmp   .imp_thunk
.imp_next_dll:
    add   ebx, 20
    jmp   .imp_dll
.imp_done:

    ; ==== 12. 执行 TLS 回调（DLL_PROCESS_ATTACH） ====
    mov   eax, [edi + 0x28]       ; optional header
    mov   ebx, [eax + 0xA8]       ; TLS dir VA (PE32 DataDirectory[9])
    test  ebx, ebx
    jz    .tls_done
    add   ebx, [edi + 0x2C]       ; TLS 目录实际地址
    mov   esi, [ebx + 0x0C]       ; AddressOfCallBacks（重定位后已是实际地址）
    test  esi, esi
    jz    .tls_done
.tls_loop:
    mov   eax, [esi]              ; 回调（重定位后已是实际地址）
    test  eax, eax
    jz    .tls_done
    push  0                       ; Reserved
    push  1                       ; DLL_PROCESS_ATTACH
    push  dword [edi + 0x2C]      ; DllHandle = base
    call  eax                     ; TLS 回调（stdcall，自动清 12 字节）
    add   esi, 4
    jmp   .tls_loop
.tls_done:

; ==== 12.5 路径 / MUI 兼容层（x86） ====
; GetModuleFileNameW(NULL) -> 实例块里的原始路径；LoadStringW(NULL,..) -> 同目录的 MUI
; 注意：[edi+0x3C] 是导入循环的临时槽，循环结束后是"最后一个 DLL"的句柄，
;       不能当 kernel32 用；这里重新 LoadLibraryA 一次。
    call  .hk_pc
.hk_pc:
    pop   ebx
    add   ebx, hk_data - .hk_pc
    lea   esi, [ebx + args_block - hk_data]     ; 实例参数块
    mov   [ebx + hk_api - hk_data], edi
    lea   eax, [ebx + str_gmha - hk_data]
    push  eax
    push  dword [ebx + hk_k32 - hk_data]
    call  dword [edi + 0x00]
    test  eax, eax
    jz    .hk_no_img
    push  0
    call  eax
    mov   [ebx + hk_img - hk_data], eax
.hk_no_img:

    lea   eax, [ebx + str_k32 - hk_data]
    push  eax
    call  dword [edi + 0x04]            ; LoadLibraryA("kernel32.dll")
    test  eax, eax
    jz    .hk_done
    mov   [ebx + hk_k32 - hk_data], eax

    movzx eax, word [esi + 0]
    movzx ecx, word [esi + 2]
    test  ecx, ecx
    jz    .hk_done
    lea   eax, [esi + eax + 6]          ; imagePath 数据（cmdlen + 4 + 2 个 NUL）
    mov   [ebx + hk_path - hk_data], eax
    mov   [ebx + hk_len - hk_data], ecx

    ; user32 句柄：已加载就用，没加载就 LoadLibraryA
    lea   eax, [ebx + str_gmha - hk_data]
    push  eax
    push  dword [ebx + hk_k32 - hk_data]
    call  dword [edi + 0x00]            ; GetProcAddress(k32,"GetModuleHandleA")
    test  eax, eax
    jz    .hk_patch
    lea   ecx, [ebx + str_u32 - hk_data]
    push  ecx
    call  eax                           ; GetModuleHandleA("user32.dll")（stdcall 自清栈）
    test  eax, eax
    jnz   .hk_have_u32
    lea   eax, [ebx + str_u32 - hk_data]
    push  eax
    call  dword [edi + 0x04]            ; LoadLibraryA("user32.dll")
.hk_have_u32:
    test  eax, eax
    jz    .hk_patch
    lea   ecx, [ebx + str_lsw - hk_data]
    push  ecx
    push  eax
    call  dword [edi + 0x00]            ; GetProcAddress(user32,"LoadStringW")
    mov   [ebx + hk_lsw - hk_data], eax

    ; 预加载 MUI：<dir>\<lang>\<base>.mui
    lea   eax, [ebx + str_l2ln - hk_data]
    push  eax
    push  dword [ebx + hk_k32 - hk_data]
    call  dword [edi + 0x00]            ; GetProcAddress(k32,"LCIDToLocaleName")
    test  eax, eax
    jz    .mui_enus
    mov   [ebx + hk_tmp - hk_data], eax
    lea   eax, [ebx + str_guil - hk_data]
    push  eax
    push  dword [ebx + hk_k32 - hk_data]
    call  dword [edi + 0x00]            ; GetProcAddress(k32,"GetUserDefaultUILanguage")
    test  eax, eax
    jz    .mui_enus
    push  0
    push  85
    lea   ecx, [ebx + hk_lang - hk_data]
    push  ecx
    push  eax
    call  dword [ebx + hk_tmp - hk_data]   ; LCIDToLocaleName(lcid,buf,85,0)
    test  eax, eax
    jz    .mui_enus
    lea   ecx, [ebx + hk_lang - hk_data]
    jmp   .mui_try
.mui_enus:
    lea   ecx, [ebx + w_enus - hk_data]
.mui_try:
    mov   [ebx + hk_langp - hk_data], ecx      ; 记住首选语言串
    lea   eax, [ebx + str_llew - hk_data]
    push  eax
    push  dword [ebx + hk_k32 - hk_data]
    call  dword [edi + 0x00]            ; GetProcAddress(k32,"LoadLibraryExW")
    test  eax, eax
    jz    .hk_patch
    mov   [ebx + hk_llew - hk_data], eax
    mov   dword [ebx + hk_swap - hk_data], 0
    mov   ecx, [ebx + hk_langp - hk_data]
    call  build_path
    test  eax, eax
    jz    .a2
    push  2
    push  0
    push  eax
    call  dword [ebx + hk_llew - hk_data]
    test  eax, eax
    jnz   .mui_ok
.a2:
    lea   ecx, [ebx + w_enus - hk_data]
    call  build_path
    test  eax, eax
    jz    .a3
    push  2
    push  0
    push  eax
    call  dword [ebx + hk_llew - hk_data]
    test  eax, eax
    jnz   .mui_ok
.a3:
    mov   dword [ebx + hk_swap - hk_data], 1
    mov   ecx, [ebx + hk_langp - hk_data]
    call  build_path
    test  eax, eax
    jz    .a4
    push  2
    push  0
    push  eax
    call  dword [ebx + hk_llew - hk_data]
    test  eax, eax
    jnz   .mui_ok
.a4:
    lea   ecx, [ebx + w_enus - hk_data]
    call  build_path
    test  eax, eax
    jz    .hk_patch
    push  2
    push  0
    push  eax
    call  dword [ebx + hk_llew - hk_data]
    test  eax, eax
    jz    .hk_patch
.mui_ok:
    mov   [ebx + hk_mui - hk_data], eax

.hk_patch:
    lea   ecx, [ebx + str_gmfw - hk_data]
    push  ecx
    push  dword [ebx + hk_k32 - hk_data]
    call  dword [edi + 0x00]            ; GetProcAddress(k32,"GetModuleFileNameW")
    mov   [ebx + hk_gmfn - hk_data], eax

    lea   ecx, [ebx + str_fmt - hk_data]
    push  ecx
    push  dword [ebx + hk_k32 - hk_data]
    call  dword [edi + 0x00]            ; GetProcAddress(k32,"FormatMessageW")
    mov   [ebx + hk_fmt - hk_data], eax

    mov   eax, [edi + 0x28]             ; optional header
    mov   eax, [eax + 0x68]             ; Import dir RVA (PE32)
    test  eax, eax
    jz    .hk_done
    add   eax, [edi + 0x2C]
    mov   [ebx + hk_desc - hk_data], eax
.hk_desc_loop:
    mov   eax, [ebx + hk_desc - hk_data]
    cmp   dword [eax + 0x0C], 0
    jz    .hk_done
    mov   ecx, [eax + 0x10]             ; FirstThunk（要改的 IAT）
    test  ecx, ecx
    jz    .hk_next_desc
    add   ecx, [edi + 0x2C]
    mov   [ebx + hk_ft - hk_data], ecx
    mov   edx, [eax + 0x00]             ; OriginalFirstThunk（名字表）
    test  edx, edx
    jz    .hk_next_desc                 ; 没有名字表就拿不到 API 名，跳过
.hk_have_oft:
    add   edx, [edi + 0x2C]
    mov   [ebx + hk_it - hk_data], edx
.hk_thunk:
    mov   ecx, [ebx + hk_ft - hk_data]
    mov   edx, [ecx]
    test  edx, edx
    jz    .hk_next_desc
    mov   esi, [ebx + hk_it - hk_data]
    mov   esi, [esi]
    test  esi, esi
    jz    .hk_next_thunk
    test  esi, 0x80000000
    jnz   .hk_next_thunk                ; 序号导入，跳过
    add   esi, [edi + 0x2C]             ; RVA -> VA
    mov   eax, [edi + 0x2C]
    cmp   esi, eax
    jb    .hk_next_thunk
    mov   edx, esi
    sub   edx, eax
    cmp   edx, 0x20000000
    jae   .hk_next_thunk
    add   esi, 2                        ; 跳过 Hint
    mov   ecx, esi
    lea   edx, [ebx + str_gmfw - hk_data]
    call  hk_streq
    test  eax, eax
    jnz   .hk_set_gmfn
    mov   ecx, esi
    lea   edx, [ebx + str_lsw - hk_data]
    call  hk_streq
    test  eax, eax
    jz    .hk_next_thunk
    mov   ecx, [ebx + hk_ft - hk_data]
    lea   edx, [ebx + shim_lsw - hk_data]
    mov   [ecx], edx
    inc   dword [ebx + hk_cnt - hk_data]
    jmp   .hk_next_thunk
    mov   ecx, esi
    lea   edx, [ebx + str_fmt - hk_data]
    call  hk_streq
    test  eax, eax
    jz    .hk_next_thunk
    cmp   dword [ebx + hk_fmt - hk_data], 0
    jz    .hk_next_thunk
    mov   ecx, [ebx + hk_ft - hk_data]
    lea   edx, [ebx + shim_fmt - hk_data]
    mov   [ecx], edx
    inc   dword [ebx + hk_cnt - hk_data]
    jmp   .hk_next_thunk
.hk_set_gmfn:
    mov   ecx, [ebx + hk_ft - hk_data]
    lea   edx, [ebx + shim_gmfn - hk_data]
    mov   [ecx], edx
    inc   dword [ebx + hk_cnt - hk_data]
.hk_next_thunk:
    mov   eax, [ebx + hk_ft - hk_data]
    add   eax, 4
    mov   [ebx + hk_ft - hk_data], eax
    mov   eax, [ebx + hk_it - hk_data]
    add   eax, 4
    mov   [ebx + hk_it - hk_data], eax
    jmp   .hk_thunk
.hk_next_desc:
    mov   eax, [ebx + hk_desc - hk_data]
    add   eax, 20
    mov   [ebx + hk_desc - hk_data], eax
    jmp   .hk_desc_loop
.hk_done:
    ; ==== 13. 跳转入口点 ====
    mov   eax, [edi + 0x20]       ; EntryPoint
    add   eax, [edi + 0x2C]       ; + base
    add   esp, 0x54
    jmp   eax

fail_late:
    add   esp, 0x54
fail_early:
    ret

; ---------------------------------------------------------------------------
; 路径 / MUI 兼容层（x86）：GetModuleFileNameW(NULL) 与 LoadStringW(NULL,..)
; ---------------------------------------------------------------------------
; ecx = 待比较串, edx = 目标串 -> eax = 1 相等 / 0 不等
hk_streq:
    push  esi
    push  edi
    mov   esi, ecx
    mov   edi, edx
.hk_cmp_loop:
    mov   al, [esi]
    mov   dl, [edi]
    cmp   al, dl
    jne   .hk_cmp_ne
    test  al, al
    jz    .hk_cmp_eq
    inc   esi
    inc   edi
    jmp   .hk_cmp_loop
.hk_cmp_ne:
    xor   eax, eax
    jmp   .hk_cmp_out
.hk_cmp_eq:
    mov   eax, 1
.hk_cmp_out:
    pop   edi
    pop   esi
    ret

shim_gmfn:
    push  ebp
    mov   ebp, esp
    push  ebx
    push  esi
    push  edi
    call  .pc
.pc:
    pop   ebx
    add   ebx, hk_data - .pc
    cmp   dword [ebp + 8], 0            ; hModule == NULL ?
    jne   .real
    mov   esi, [ebx + hk_path - hk_data]
    test  esi, esi
    jz    .real
    mov   ecx, [ebx + hk_len - hk_data]
    shr   ecx, 1
    jz    .real
    mov   edi, [ebp + 12]               ; lpFilename
    mov   edx, [ebp + 16]               ; nSize
    dec   edx
    jle   .real
    cmp   ecx, edx
    jbe   .len_ok
    mov   ecx, edx
.len_ok:
    mov   edx, ecx
    cld
    rep   movsw
    mov   word [edi], 0
    mov   eax, edx
    pop   edi
    pop   esi
    pop   ebx
    pop   ebp
    ret   12
.real:
    mov   eax, [ebx + hk_gmfn - hk_data]
    pop   edi
    pop   esi
    pop   ebx
    pop   ebp
    jmp   eax

shim_lsw:
    ; stdcall: LoadStringW(hInstance, uID, lpBuffer, cchBufferMax)
    push  ebp
    mov   ebp, esp
    push  ebx
    push  esi
    call  .pc
.pc:
    pop   ebx
    add   ebx, hk_data - .pc

    push  dword [ebp + 0x14]
    push  dword [ebp + 0x10]
    push  dword [ebp + 0x0C]
    push  dword [ebp + 0x08]
    call  dword [ebx + hk_lsw - hk_data]
    test  eax, eax
    jnz   .out

    ; 真函数失败（多为 .rsrc 里没有 RT_STRING，字符串在 MUI 里）→ 换 MUI 再试
    mov   esi, [ebx + hk_mui - hk_data]
    test  esi, esi
    jz    .out
    push  dword [ebp + 0x14]
    push  dword [ebp + 0x10]
    push  dword [ebp + 0x0C]
    push  esi
    call  dword [ebx + hk_lsw - hk_data]
.out:
    pop   esi
    pop   ebx
    pop   ebp
    ret   16

; FormatMessageW shim：lpSource 指向自建镜像时换成 datafile 句柄
; （真函数查 Ldr 找不到我们的模块，会直接在系统 DLL 里 AV）
shim_fmt:
    mov   eax, [esp + 8]                ; lpSource
    test  eax, eax
    jz    .sf_jmp
    push  ebx
    call  .sf_pc
.sf_pc:
    pop   ebx
    add   ebx, hk_data - .sf_pc
    cmp   eax, [ebx + hk_img - hk_data]
    pop   ebx
    jne   .sf_jmp
    push  ecx
    push  edx
    push  esi
    push  edi
    push  eax
    call  hk_dfile_get
    mov   [esp + 0x1C], eax             ; 覆盖调用方的 lpSource 槽
    pop   eax
    pop   edi
    pop   esi
    pop   edx
    pop   ecx
.sf_jmp:
    push  ebx
    call  .sf_pc3
.sf_pc3:
    pop   ebx
    add   ebx, hk_data - .sf_pc3
    mov   eax, [ebx + hk_fmt - hk_data]
    pop   ebx
    jmp   eax

; -> eax = LoadLibraryExW(<imagePath>, 0, LOAD_LIBRARY_AS_DATAFILE)，缓存
hk_dfile_get:
    push  ebx
    call  .df_pc
.df_pc:
    pop   ebx
    add   ebx, hk_data - .df_pc
    mov   eax, [ebx + hk_dfile - hk_data]
    test  eax, eax
    jnz   .df_out
    push  2
    push  0
    push  dword [ebx + hk_path - hk_data]
    call  dword [ebx + hk_llew - hk_data]
    mov   [ebx + hk_dfile - hk_data], eax
.df_out:
    pop   ebx
    ret

; ecx = 语言名（宽字符）-> eax = "<dir>\<lang>\<base>.mui" 或 0
build_path:
    push  ebx
    push  esi
    push  edi
    call  .pc
.pc:
    pop   ebx
    add   ebx, hk_data - .pc
    mov   [ebx + hk_langp - hk_data], ecx
    mov   esi, [ebx + hk_path - hk_data]
    test  esi, esi
    jz    .fail
    mov   eax, [ebx + hk_len - hk_data]
    shr   eax, 1
    test  eax, eax
    jz    .fail
    mov   [ebx + hk_total - hk_data], eax
    xor   edx, edx
    xor   ecx, ecx
.scan:
    cmp   ecx, [ebx + hk_total - hk_data]
    jae   .scanned
    mov   ax, [esi + ecx * 2]
    cmp   ax, 0x5C
    jne   .next
    lea   edx, [ecx + 1]
.next:
    inc   ecx
    jmp   .scan
.scanned:
    test  edx, edx
    jz    .fail
    mov   [ebx + hk_dir - hk_data], edx
    lea   edi, [ebx + hk_buf - hk_data]
    xor   eax, eax
.cp:
    cmp   eax, edx
    jae   .cp_done
    mov   cx, [esi + eax * 2]
    mov   [edi], cx
    add   edi, 2
    inc   eax
    jmp   .cp
.cp_done:
    ; 可选：把目录里的 "SysWOW64" 换成 "System32"（等长）
    cmp   dword [ebx + hk_swap - hk_data], 0
    jz    .no_swap
    mov   edx, [ebx + hk_dir - hk_data]
    cmp   edx, 8
    jb    .no_swap
    lea   esi, [ebx + hk_buf - hk_data]
    lea   eax, [esi + edx * 2 - 16]
.sw_scan:
    cmp   esi, eax
    ja    .no_swap
    cmp   word [esi], 0x53
    jne   .sw_next
    cmp   word [esi + 2], 0x79
    jne   .sw_next
    cmp   word [esi + 4], 0x73
    jne   .sw_next
    cmp   word [esi + 6], 0x57
    jne   .sw_next
    cmp   word [esi + 8], 0x4F
    jne   .sw_next
    cmp   word [esi + 10], 0x57
    jne   .sw_next
    cmp   word [esi + 12], 0x36
    jne   .sw_next
    cmp   word [esi + 14], 0x34
    jne   .sw_next
    mov   word [esi + 6], 0x74
    mov   word [esi + 8], 0x65
    mov   word [esi + 10], 0x6D
    mov   word [esi + 12], 0x33
    mov   word [esi + 14], 0x32
    jmp   .no_swap
.sw_next:
    add   esi, 2
    jmp   .sw_scan
.no_swap:
    mov   ecx, [ebx + hk_langp - hk_data]
.lang:
    mov   ax, [ecx]
    test  ax, ax
    jz    .lang_done
    mov   [edi], ax
    add   edi, 2
    add   ecx, 2
    jmp   .lang
.lang_done:
    mov   word [edi], 0x5C
    add   edi, 2
    mov   esi, [ebx + hk_path - hk_data]
    mov   eax, [ebx + hk_dir - hk_data]
    lea   ecx, [esi + eax * 2]
.base:
    mov   ax, [ecx]
    test  ax, ax
    jz    .base_done
    mov   [edi], ax
    add   edi, 2
    add   ecx, 2
    jmp   .base
.base_done:
    mov   word [edi], 0x002E
    mov   word [edi + 2], 0x006D
    mov   word [edi + 4], 0x0075
    mov   word [edi + 6], 0x0069
    mov   word [edi + 8], 0
    lea   eax, [ebx + hk_buf - hk_data]
    jmp   .ret
.fail:
    xor   eax, eax
.ret:
    pop   edi
    pop   esi
    pop   ebx
    ret


; ---------------------------------------------------------------------------
; 桩内字符串表（不可执行区，step 13 已 jmp 走）
; ---------------------------------------------------------------------------
str_kb:      db 'kernelbase.dll', 0
str_gclw:    db 'GetCommandLineW', 0
str_gcla:    db 'GetCommandLineA', 0

; 路径 / MUI 兼容层数据区
hk_data:
hk_api:    dd 0
hk_k32:    dd 0
hk_gmfn:   dd 0
hk_lsw:    dd 0
hk_mui:    dd 0
hk_llew:   dd 0
hk_tmp:    dd 0
hk_img:    dd 0
hk_ft:     dd 0
hk_it:     dd 0
hk_path:   dd 0
hk_len:    dd 0
hk_langp:  dd 0
hk_dir:    dd 0
hk_desc:   dd 0
hk_total:  dd 0
hk_cnt:    dd 0
hk_swap:   dd 0
hk_fmt:    dd 0
hk_dfile:  dd 0
ansi_buf:  times 0x100 db 0
hk_lang:   times 0x100 db 0
hk_buf:    times 0x300 db 0
w_enus:    dw 'e','n','-','U','S',0
str_k32:   db 'kernel32.dll',0
str_gmha:  db 'GetModuleHandleA',0
str_u32:   db 'user32.dll',0
str_lsw:   db 'LoadStringW',0
str_gmfw:  db 'GetModuleFileNameW',0
str_llew:  db 'LoadLibraryExW',0
str_guil:  db 'GetUserDefaultUILanguage',0
str_l2ln:  db 'LCIDToLocaleName',0
str_fmt:   db 'FormatMessageW',0


; ---------------------------------------------------------------------------
; 桩结束标记 —— args block 紧跟其后
; ---------------------------------------------------------------------------
args_block:

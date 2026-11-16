// ldrlab2.c —— 诊断用：把 PE 映射进内存再跳入口，可选打补丁 / IAT 日志
// 用法: ldrlab2.exe <pe> [f1f2f4Th]
//   f1 PEB.ImageBaseAddress   f2 ImagePathName   f4 Ldr 注册   T TLS   h IAT 日志
#include <windows.h>
#include <stdio.h>
#include <wchar.h>
#include <string.h>
#include <stdarg.h>

typedef struct _MY_UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} MY_UNICODE_STRING;

typedef struct _MY_PEB {
    BYTE  InheritedAddressSpace; BYTE ReadImageFileExecOptions; BYTE BeingDebugged; BYTE Padding0;
    ULONG Padding1;
    PVOID Mutant;            // +0x08
    PVOID ImageBaseAddress;  // +0x10
    PVOID Ldr;               // +0x18
    PVOID ProcessParameters; // +0x20
} MY_PEB;

typedef struct _MY_LDR_DATA {
    ULONG Length; BOOLEAN Initialized; PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;           // +0x10
    LIST_ENTRY InMemoryOrderModuleList;         // +0x20
    LIST_ENTRY InInitializationOrderModuleList; // +0x30
} MY_LDR_DATA;

typedef struct _MY_LDR_ENTRY {
    LIST_ENTRY InLoadOrderLinks;            // +0x00
    LIST_ENTRY InMemoryOrderLinks;          // +0x10
    LIST_ENTRY InInitializationOrderLinks;  // +0x20
    PVOID DllBase;                          // +0x30
    PVOID EntryPoint;                       // +0x38
    ULONG SizeOfImage;                      // +0x40
    MY_UNICODE_STRING FullDllName;          // +0x48
    MY_UNICODE_STRING BaseDllName;          // +0x58
} MY_LDR_ENTRY;

static void die(const char *m) { fprintf(stderr, "[-] %s (err=%lu)\n", m, GetLastError()); ExitProcess(2); }

static void apply_reloc(BYTE *base, IMAGE_DATA_DIRECTORY *d)
{
    if (!d->Size) return;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
    ULONGLONG delta = (ULONGLONG)(ULONG_PTR)base - nt->OptionalHeader.ImageBase;
    if (delta == 0) return;
    BYTE *p = base + d->VirtualAddress, *end = p + d->Size;
    while (p < end) {
        PIMAGE_BASE_RELOCATION blk = (PIMAGE_BASE_RELOCATION)p;
        if (!blk->SizeOfBlock) break;
        int n = (blk->SizeOfBlock - 8) / 2;
        PWORD ent = (PWORD)(p + 8);
        for (int i = 0; i < n; i++) {
            int type = ent[i] >> 12, off = ent[i] & 0xFFF;
            BYTE *t = base + blk->VirtualAddress + off;
            if (type == 10) *(ULONGLONG *)t += delta;
            else if (type == 3) *(ULONG *)t += (ULONG)delta;
        }
        p += blk->SizeOfBlock;
    }
}

static int (WINAPI *real_LoadStringW)(HINSTANCE, UINT, LPWSTR, int);
static DWORD (WINAPI *real_GetFileVersionInfoSizeExW)(DWORD, LPCWSTR, LPDWORD);
static BOOL  (WINAPI *real_GetFileVersionInfoExW)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
static BOOL  (WINAPI *real_VerQueryValueW)(LPCVOID, LPCWSTR, LPVOID *, PUINT);
static DWORD (WINAPI *real_GetModuleFileNameW)(HMODULE, LPWSTR, DWORD);
static void dumpw(const char *tag, LPCWSTR w)
{
    char b[512];
    WideCharToMultiByte(CP_UTF8, 0, w ? w : L"<null>", -1, b, sizeof(b), NULL, NULL);
    fprintf(stderr, "[hook] %s path=[%s]\n", tag, b);
}
static wchar_t g_force[MAX_PATH];

static DWORD WINAPI my_GetModuleFileNameW(HMODULE h, LPWSTR buf, DWORD n)
{
    DWORD r;
    if (h == NULL && g_force[0]) {
        DWORD len = (DWORD)wcslen(g_force);
        if (len >= n) len = n - 1;
        memcpy(buf, g_force, len * sizeof(wchar_t));
        buf[len] = 0;
        r = len;
    } else {
        r = real_GetModuleFileNameW(h, buf, n);
    }
    dumpw("GetModuleFileNameW", buf);
    return r;
}
static DWORD (WINAPI *real_FormatMessageW)(DWORD, LPCVOID, DWORD, DWORD, LPWSTR, DWORD, va_list *);

static HMODULE g_mui;
static wchar_t g_mui_path[MAX_PATH];

static HMODULE load_mui(void)
{
    if (g_mui) return g_mui;
    if (!g_force[0]) return NULL;
    // <dir>\<lang>\<basename>.mui
    const wchar_t *bn = wcsrchr(g_force, (wchar_t)0x5C);
    if (!bn) return NULL;
    wchar_t dir[MAX_PATH];
    size_t dlen = (size_t)(bn - g_force);
    wmemcpy(dir, g_force, dlen);
    dir[dlen] = 0;
    wchar_t lang[85] = L"en-US";
    LCIDToLocaleName(GetUserDefaultUILanguage(), lang, 85, 0);
    static const wchar_t *tries[] = { L"zh-CN", L"en-US" };
    for (int i = 0; i < 3; i++) {
        const wchar_t *l = (i == 0) ? lang : tries[i - 1];
        swprintf(g_mui_path, MAX_PATH, L"%s%c%s%c%s.mui", dir, (wchar_t)0x5C, l, (wchar_t)0x5C, bn + 1);
        g_mui = LoadLibraryExW(g_mui_path, NULL, LOAD_LIBRARY_AS_DATAFILE);
        if (g_mui) { dumpw("MUI loaded", g_mui_path); return g_mui; }
    }
    dumpw("MUI failed", g_mui_path);
    return NULL;
}

static int WINAPI my_LoadStringW(HINSTANCE h, UINT id, LPWSTR buf, int n)
{
    if (h == NULL) {
        HMODULE m = load_mui();
        if (m) h = m;
    }
    int r = real_LoadStringW(h, id, buf, n);
    fprintf(stderr, "[hook] LoadStringW(h=%p id=%u) -> %d err=%lu\n", (void *)h, id, r, GetLastError());
    return r;
}
static DWORD WINAPI my_GetFileVersionInfoSizeExW(DWORD f, LPCWSTR path, LPDWORD h)
{
    dumpw("GetFileVersionInfoSizeExW", path);
    DWORD r = real_GetFileVersionInfoSizeExW(f, path, h);
    fprintf(stderr, "[hook] GetFileVersionInfoSizeExW -> %lu err=%lu\n", r, GetLastError());
    return r;
}
static BOOL WINAPI my_GetFileVersionInfoExW(DWORD f, LPCWSTR path, DWORD a, DWORD len, LPVOID data)
{
    BOOL r = real_GetFileVersionInfoExW(f, path, a, len, data);
    fprintf(stderr, "[hook] GetFileVersionInfoExW -> %d err=%lu\n", r, GetLastError());
    return r;
}
static BOOL WINAPI my_VerQueryValueW(LPCVOID blk, LPCWSTR sub, LPVOID *out, PUINT len)
{
    dumpw("VerQueryValueW", sub);
    BOOL r = real_VerQueryValueW(blk, sub, out, len);
    fprintf(stderr, "[hook] VerQueryValueW -> %d err=%lu\n", r, GetLastError());
    return r;
}
static DWORD WINAPI my_FormatMessageW(DWORD fl, LPCVOID src, DWORD id, DWORD lang, LPWSTR buf, DWORD n, va_list *args)
{
    DWORD r = real_FormatMessageW(fl, src, id, lang, buf, n, args);
    fprintf(stderr, "[hook] FormatMessageW(flags=0x%lx src=%p id=%lu) -> %lu err=%lu buf=[%ls]
", fl, src, id, r, GetLastError(), (r && buf) ? buf : L"");
    return r;
}


/* ---- 输出路径钩子：_write / WriteFile / WriteConsoleW / GetConsoleMode ---- */
static int (__cdecl *real_write)(int, const void *, unsigned);
static BOOL (WINAPI *real_WriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
static BOOL (WINAPI *real_WriteConsoleW)(HANDLE, const void *, DWORD, LPDWORD, LPVOID);
static BOOL (WINAPI *real_GetConsoleMode)(HANDLE, LPDWORD);
static int __cdecl my_write(int fd, const void *buf, unsigned n)
{
    int r = real_write(fd, buf, n);
    fprintf(stderr, "[hook] _write(fd=%d n=%u) -> %d err=%lu first=%.40s\n",
            fd, n, r, GetLastError(), (const char *)buf);
    return r;
}
static BOOL WINAPI my_WriteFile(HANDLE h, LPCVOID b, DWORD n, LPDWORD w, LPOVERLAPPED o)
{
    BOOL r = real_WriteFile(h, b, n, w, o);
    fprintf(stderr, "[hook] WriteFile(h=%p n=%lu) -> %d written=%lu err=%lu\n",
            (void *)h, (unsigned long)n, r, (unsigned long)(w ? *w : 0), GetLastError());
    return r;
}
static BOOL WINAPI my_WriteConsoleW(HANDLE h, const void *b, DWORD n, LPDWORD w, LPVOID r0)
{
    BOOL r = real_WriteConsoleW(h, b, n, w, r0);
    fprintf(stderr, "[hook] WriteConsoleW(h=%p n=%lu) -> %d written=%lu err=%lu\n",
            (void *)h, (unsigned long)n, r, (unsigned long)(w ? *w : 0), GetLastError());
    return r;
}
static BOOL WINAPI my_GetConsoleMode(HANDLE h, LPDWORD m)
{
    BOOL r = real_GetConsoleMode(h, m);
    fprintf(stderr, "[hook] GetConsoleMode(h=%p) -> %d mode=%lx err=%lu\n",
            (void *)h, r, (unsigned long)(m ? *m : 0), GetLastError());
    return r;
}

static void do_imports(BYTE *base, IMAGE_DATA_DIRECTORY *d, int hooks)
{
    if (!d->Size) return;
    PIMAGE_IMPORT_DESCRIPTOR imp = (PIMAGE_IMPORT_DESCRIPTOR)(base + d->VirtualAddress);
    for (; imp->Name; imp++) {
        const char *dll = (const char *)(base + imp->Name);
        HMODULE h = LoadLibraryA(dll);
        if (!h) die(dll);
        if (!imp->OriginalFirstThunk) continue;
        PIMAGE_THUNK_DATA oft = (PIMAGE_THUNK_DATA)(base + imp->OriginalFirstThunk);
        PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA)(base + imp->FirstThunk);
        for (; oft->u1.AddressOfData; oft++, iat++) {
            FARPROC fn;
            const char *nm = NULL;
            if (oft->u1.Ordinal & 0x8000000000000000ULL)
                fn = GetProcAddress(h, (LPCSTR)(ULONG_PTR)(oft->u1.Ordinal & 0xFFFF));
            else {
                nm = (const char *)(base + oft->u1.AddressOfData + 2);
                fn = GetProcAddress(h, nm);
            }
            if (!fn) { fprintf(stderr, "[-] import fail %s!%s\n", dll, nm ? nm : "?"); ExitProcess(3); }
            iat->u1.Function = (ULONGLONG)fn;
            if (!hooks || !nm) continue;
            if (!strcmp(nm, "LoadStringW")) { real_LoadStringW = (void *)fn; iat->u1.Function = (ULONGLONG)my_LoadStringW; }
            else if (!strcmp(nm, "GetFileVersionInfoSizeExW")) { real_GetFileVersionInfoSizeExW = (void *)fn; iat->u1.Function = (ULONGLONG)my_GetFileVersionInfoSizeExW; }
            else if (!strcmp(nm, "GetFileVersionInfoExW")) { real_GetFileVersionInfoExW = (void *)fn; iat->u1.Function = (ULONGLONG)my_GetFileVersionInfoExW; }
            else if (!strcmp(nm, "VerQueryValueW")) { real_VerQueryValueW = (void *)fn; iat->u1.Function = (ULONGLONG)my_VerQueryValueW; }
            else if (!strcmp(nm, "GetModuleFileNameW")) { real_GetModuleFileNameW = (void *)fn; iat->u1.Function = (ULONGLONG)my_GetModuleFileNameW; }
            else if (!strcmp(nm, "FormatMessageW")) { real_FormatMessageW = (void *)fn; iat->u1.Function = (ULONGLONG)my_FormatMessageW; }
        }
    }
}

static void do_tls(BYTE *base, IMAGE_DATA_DIRECTORY *d)
{
    if (!d->Size) return;
    IMAGE_TLS_DIRECTORY *t = (IMAGE_TLS_DIRECTORY *)(base + d->VirtualAddress);
    DWORD idx = TlsAlloc();
    if (idx == TLS_OUT_OF_INDEXES) return;
    if (t->AddressOfIndex) *(DWORD *)t->AddressOfIndex = idx;
    SIZE_T len = (SIZE_T)(t->EndAddressOfRawData - t->StartAddressOfRawData) + t->SizeOfZeroFill;
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, len ? len : 8, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buf && t->StartAddressOfRawData)
        memcpy(buf, (void *)t->StartAddressOfRawData, (SIZE_T)(t->EndAddressOfRawData - t->StartAddressOfRawData));
    if (buf) ((PVOID *)__readgsqword(0x58))[idx] = buf;
    if (t->AddressOfCallBacks) {
        for (PIMAGE_TLS_CALLBACK *cb = (PIMAGE_TLS_CALLBACK *)t->AddressOfCallBacks; *cb; cb++)
            (*cb)((PVOID)base, DLL_PROCESS_ATTACH, NULL);
    }
}


/* 在进程内存里把宿主 exe 路径替换成目标路径（试探 kernelbase 的 exe 路径缓存） */
static void rewrite_exe_path_cache(const wchar_t *from, const wchar_t *to)
{
    SIZE_T flen = wcslen(from), tlen = wcslen(to);
    if (tlen > flen) return;
    BYTE *p = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    int hits = 0;
    while (VirtualQuery(p, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY))) {
            BYTE *base = (BYTE *)mbi.BaseAddress, *end = base + mbi.RegionSize;
            for (BYTE *q = base; q + flen * 2 <= end; q += 2) {
                if (memcmp(q, from, flen * 2) == 0 && q[flen * 2] == 0) {
                    memcpy(q, to, tlen * 2);
                    memset(q + tlen * 2, 0, (flen - tlen) * 2 + 2);
                    hits++;
                }
            }
        }
        p = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
    }
    fprintf(stderr, "[ldrlab2] path cache hits=%d\n", hits);
}

int main(int argc, char **argv)
{
    if (argc < 2) { printf("usage: ldrlab2.exe <pe> [f1f2f4Th]\n"); return 1; }
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);

    HANDLE f = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) die("open");
    DWORD sz = GetFileSize(f, NULL);
    BYTE *raw = (BYTE *)malloc(sz);
    DWORD rd;
    ReadFile(f, raw, sz, &rd, NULL);
    CloseHandle(f);

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)raw;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(raw + dos->e_lfanew);
    BYTE *base = (BYTE *)VirtualAlloc((PVOID)nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfImage,
                                      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!base)
        base = (BYTE *)VirtualAlloc(NULL, nt->OptionalHeader.SizeOfImage,
                                    MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!base) die("virtualalloc");

    memcpy(base, raw, nt->OptionalHeader.SizeOfHeaders);
    PIMAGE_SECTION_HEADER sh = IMAGE_FIRST_SECTION(nt);
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        DWORD n = sh[i].SizeOfRawData < sh[i].Misc.VirtualSize ? sh[i].SizeOfRawData : sh[i].Misc.VirtualSize;
        if (n) memcpy(base + sh[i].VirtualAddress, raw + sh[i].PointerToRawData, n);
    }

    apply_reloc(base, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]);
    const char *flags = argc > 2 ? argv[2] : "";
    do_imports(base, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT], strchr(flags, 'h') != NULL);
    if (strchr(flags, 'T')) do_tls(base, &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS]);

    MY_PEB *peb = (MY_PEB *)(ULONG_PTR)__readgsqword(0x60);

    if (strstr(flags, "f1")) peb->ImageBaseAddress = base;

    if (strstr(flags, "f2")) {
        MY_UNICODE_STRING *us = (MY_UNICODE_STRING *)((BYTE *)peb->ProcessParameters + 0x60);
        static wchar_t wpath[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wpath, MAX_PATH);
        USHORT cb = (USHORT)(wcslen(wpath) * 2);
        us->Length = cb;
        us->MaximumLength = (USHORT)(cb + 2);
        us->Buffer = wpath;
    }

    if (strstr(flags, "f4")) {
        MY_LDR_ENTRY *e = (MY_LDR_ENTRY *)VirtualAlloc(NULL, sizeof(MY_LDR_ENTRY) + 0x800,
                                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        static wchar_t wfull[MAX_PATH], wbase[MAX_PATH];
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, wfull, MAX_PATH);
        const wchar_t *bn = wcsrchr(wfull, L'\\');
        wcscpy(wbase, bn ? bn + 1 : wfull);
        wchar_t *buf = (wchar_t *)((BYTE *)e + sizeof(MY_LDR_ENTRY));
        wcscpy(buf, wfull);
        wchar_t *buf2 = buf + wcslen(wfull) + 1;
        wcscpy(buf2, wbase);

        e->DllBase = base;
        e->EntryPoint = base + nt->OptionalHeader.AddressOfEntryPoint;
        e->SizeOfImage = nt->OptionalHeader.SizeOfImage;
        e->FullDllName.Buffer = buf;
        e->FullDllName.Length = (USHORT)(wcslen(buf) * 2);
        e->FullDllName.MaximumLength = (USHORT)(wcslen(buf) * 2 + 2);
        e->BaseDllName.Buffer = buf2;
        e->BaseDllName.Length = (USHORT)(wcslen(buf2) * 2);
        e->BaseDllName.MaximumLength = (USHORT)(wcslen(buf2) * 2 + 2);

        MY_LDR_DATA *ldr = (MY_LDR_DATA *)peb->Ldr;
        LIST_ENTRY *lists[3] = { &ldr->InLoadOrderModuleList, &ldr->InMemoryOrderModuleList,
                                 &ldr->InInitializationOrderModuleList };
        LIST_ENTRY *mine[3] = { &e->InLoadOrderLinks, &e->InMemoryOrderLinks, &e->InInitializationOrderLinks };
        for (int i = 0; i < 3; i++) {
            mine[i]->Flink = lists[i]->Flink;
            mine[i]->Blink = lists[i];
            lists[i]->Flink->Blink = mine[i];
            lists[i]->Flink = mine[i];
        }
    }

    {
        BYTE *pp = (BYTE *)peb->ProcessParameters;
        MY_UNICODE_STRING *ip = (MY_UNICODE_STRING *)(pp + 0x60);
        MY_UNICODE_STRING *cl = (MY_UNICODE_STRING *)(pp + 0x70);
        dumpw("PP.ImagePathName", ip->Buffer);
        dumpw("PP.CommandLine", cl->Buffer);
        fprintf(stderr, "[ldrlab2] PEB.ImageBase=%p", peb->ImageBaseAddress);
    }
    {
        wchar_t t[MAX_PATH] = {0};
        GetModuleFileNameW(NULL, t, MAX_PATH);
        dumpw("direct GetModuleFileNameW(NULL)", t);
    }
    if (strchr(flags, 'G')) {
        MultiByteToWideChar(CP_ACP, 0, argv[1], -1, g_force, MAX_PATH);
        { wchar_t tmp[MAX_PATH]; GetFullPathNameW(g_force, MAX_PATH, tmp, NULL); wcscpy(g_force, tmp); }
        dumpw("forced module path", g_force);
    }
    if (strchr(flags, 'R')) {
        wchar_t host[MAX_PATH] = {0};
        real_GetModuleFileNameW(NULL, host, MAX_PATH);
        rewrite_exe_path_cache(host, g_force);
    }
    fprintf(stderr, "[ldrlab2] base=%p flags=[%s]\n", (void *)base, flags);
    fflush(stderr);
    ((int (WINAPI *)(PVOID, DWORD, LPVOID))(base + nt->OptionalHeader.AddressOfEntryPoint))(
        base, DLL_PROCESS_ATTACH, NULL);
    return 0;
}

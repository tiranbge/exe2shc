#include <windows.h>
#include <stdio.h>
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } USTR;
typedef struct { BYTE pad[0x20]; PVOID ProcessParameters; } PEB_MINI;
typedef struct { BYTE pad[0x70]; USTR CommandLine; } PP_MINI;
int main(int argc, char **argv)
{
    PEB_MINI *peb = (PEB_MINI *)__readgsqword(0x60);
    PP_MINI *pp = (PP_MINI *)peb->ProcessParameters;
    printf("GetCommandLineA=[%s]\n", GetCommandLineA());
    printf("GetCommandLineW=[%ls]\n", GetCommandLineW());
    printf("PEB.CommandLine=[%ls] len=%u\n", pp->CommandLine.Buffer, pp->CommandLine.Length / 2);
    printf("argc=%d argv0=[%s]\n", argc, argc ? argv[0] : "");
    return 0;
}

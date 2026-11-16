#include <windows.h>
#include <stdio.h>
int main(void){
    wchar_t b[300]; b[0]=0;
    DWORD n = GetModuleFileNameW(NULL, b, 300);
    wprintf(L"GMN n=%lu path=[%ls]\n", (unsigned long)n, b);
    wchar_t s2[64]; s2[0]=0;
    DWORD m = GetModuleFileNameW(NULL, s2, 8);
    wprintf(L"small n=%lu path=[%ls]\n", (unsigned long)m, s2);
    return 0;
}

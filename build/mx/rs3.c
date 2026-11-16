#include <windows.h>
#include <stdio.h>
int main(void)
{
    wchar_t a[128] = {0}, b[128] = {0};
    int n0 = LoadStringW(NULL, 1, a, 128);  DWORD e0 = GetLastError();
    int n1 = LoadStringW(GetModuleHandleW(NULL), 1, b, 128);  DWORD e1 = GetLastError();
    printf("LoadStringW(NULL)  ret=%d buf=[%ls] err=%lu\n", n0, a, (unsigned long)e0);
    printf("LoadStringW(hMod)  ret=%d buf=[%ls] err=%lu\n", n1, b, (unsigned long)e1);
    return 0;
}

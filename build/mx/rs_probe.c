#include <windows.h>
#include <stdio.h>
int main(void)
{
    wchar_t path[MAX_PATH] = {0};
    GetModuleFileNameW(NULL, path, MAX_PATH);
    printf("ModuleFileName(NULL)=[%ls]\n", path);
    printf("GetModuleHandle(NULL)=%p\n", (void *)GetModuleHandleW(NULL));
    HMODULE me = NULL;
    DWORD err = 0;
    HRSRC r = FindResourceW(NULL, MAKEINTRESOURCEW(1), (LPCWSTR)RT_STRING);
    err = GetLastError();
    printf("FindResource(NULL,1,RT_STRING)=%p err=%lu\n", (void *)r, err);
    me = GetModuleHandleW(L"whoami.exe");
    printf("GetModuleHandleW(whoami.exe)=%p\n", (void *)me);
    return 0;
}

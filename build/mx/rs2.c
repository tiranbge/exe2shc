#include <windows.h>
#include <stdio.h>
int main(void)
{
    wchar_t buf[128] = {0};
    HMODULE h = GetModuleHandleW(NULL);
    int n = LoadStringW(h, 1, buf, 128);
    printf("hmod=%p LoadStringW ret=%d buf=[%ls] err=%lu\n", (void *)h, n, buf, GetLastError());
    /* 直接用资源 API 复核 */
    HRSRC r = FindResourceW(h, MAKEINTRESOURCEW(1), (LPCWSTR)RT_STRING);
    printf("FindResource=%p err=%lu\n", (void *)r, GetLastError());
    if (r) {
        HGLOBAL g = LoadResource(h, r);
        printf("LoadResource=%p SizeofResource=%lu\n", (void *)g, (unsigned long)SizeofResource(h, r));
    }
    return 0;
}

#include <stdio.h>
#include <windows.h>
__thread int g_tls = 1000;
static void NTAPI cb(PVOID h, DWORD reason, PVOID r) { if (reason == 1) printf("TLS-CB attach\n"); }
extern "C" PIMAGE_TLS_CALLBACK p_cb __attribute__((section(".CRT$XLB"), used)) = cb;
int main(void) { g_tls += 235; printf("TLS-VAR %d\n", g_tls); return 0; }

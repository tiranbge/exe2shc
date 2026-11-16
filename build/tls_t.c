#include <stdio.h>
__thread int tls_var = 1234;
__thread char tls_buf[32];

static void __stdcall tls_cb(void *h, unsigned long reason, void *pv)
{
    if (reason == 1) printf("[cb] DLL_PROCESS_ATTACH\n");
}

static void (*const p_cb)(void *, unsigned long, void *) __attribute__((section(".CRT$XLB"), used)) = tls_cb;

int main(void)
{
    tls_var += 1;
    tls_buf[0] = 'A';
    tls_buf[1] = 0;
    printf("tls=%d buf=%s\n", tls_var, tls_buf);
    return 0;
}

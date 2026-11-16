#include <stdio.h>
__thread int v = 7;
int main(void){ v += 5; printf("v=%d\n", v); return 0; }

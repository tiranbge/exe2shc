#include <stdio.h>
int main(void){ fprintf(stderr, "STDERR-OK\n"); printf("STDOUT-OK\n"); fflush(stdout); return 3; }

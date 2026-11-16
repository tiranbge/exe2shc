#include <stdio.h>
int main(int argc, char **argv) {
    printf("C-HELLO argc=%d\n", argc);
    for (int i = 1; i < argc; i++) printf("  arg[%d]=%s\n", i, argv[i]);
    return 7;
}

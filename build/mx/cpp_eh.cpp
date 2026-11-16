#include <cstdio>
#include <stdexcept>
#include <string>
static int deep(int n) { if (n == 0) throw std::runtime_error("boom-at-zero"); return deep(n - 1) + 1; }
int main() {
    int got = -1;
    try { got = deep(5); }
    catch (const std::exception &e) { printf("CPP-CAUGHT %s\n", e.what()); got = 42; }
    try { throw std::string("str"); } catch (const std::string &s) { printf("CPP-STR %s\n", s.c_str()); }
    printf("CPP-DONE got=%d\n", got);
    return got == 42 ? 0 : 1;
}

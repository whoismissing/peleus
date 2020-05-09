#include <stdio.h>

void foo() {
    puts("this is a foo debug string");
}

void bar() {
    puts("this is a bar debug string");
}

int main() {
    foo();
    bar();

    return 0;
}

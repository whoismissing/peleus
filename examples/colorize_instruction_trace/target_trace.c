#include <stdio.h>
#include <stdlib.h>

// gcc target_trace.c -no-pie

void foo() {
    puts("foo");
}

void bar() {
    puts("bar");
}

int main(int argc, char *argv[]) {

    if (argc < 2) {
        return 1;
    }

    int input = atoi(argv[1]);

    printf("%d\n", input);

    switch (input) {
        case 1:
            foo();
            break;
        case 2:
            bar();
            break;
        default:
            break;
    }

    return 0;

}

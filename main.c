#include <stdint.h>
#include <stdio.h>

uint32_t f(uint32_t, uint32_t);

int main(void) {
    int i = 1;
    int j = 2;
    printf("%d + %d = %d\n", i, j, f(i, j));
}

#include <stdint.h>
#include <assert.h>

uint64_t control(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

int main(void) {
    assert(control(0, 1, 2, 3, 4, 5, 6) == 21);
}

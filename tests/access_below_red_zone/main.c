#include <stdint.h>
#include <assert.h>

void access_below_red_zone(void);

int main(void) {
    access_below_red_zone();
}

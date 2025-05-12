#include <stdint.h>
#include <assert.h>

void access_within_red_zone(void);

int main(void) {
    access_within_red_zone();
}

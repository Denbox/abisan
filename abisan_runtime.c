#define _GNU_SOURCE

#include <sys/mman.h> // for mmap, PROT_READ, PROT_WRITE, MAP_PRIVATE, MAP_ANONYMOUS, MAP_FAILED
#include <unistd.h>   // for getpagesize
#include <stdlib.h>   // for exit, EXIT_FAILURE

static void __attribute__((constructor)) abisan_runtime_init(void) {
    // Shadow stack
    void *mmap_rc = mmap((void *)0xdadf000, getpagesize(), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (mmap_rc == MAP_FAILED) {
        exit(EXIT_FAILURE);
    }
}

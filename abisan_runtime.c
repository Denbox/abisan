#include <stdio.h> // for fprintf, stderr
#include <stdint.h> // for uint64_t
#include <stdlib.h> // for exit, EXIT_FAILURE

// Maybe should be packed, but will be fine as long as everything remains 8-byte
struct abisan_shadow_stack_frame {
    uint64_t rbx;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t retaddr;
};

#define SHADOW_STACK_SIZE (10)
struct abisan_shadow_stack_frame ABISAN_SHADOW_STACK_BASE[SHADOW_STACK_SIZE];
struct abisan_shadow_stack_frame *abisan_shadow_stack_pointer = ABISAN_SHADOW_STACK_BASE;

[[noreturn]] void abisan_fail(void) {
    fprintf(stderr, "ABISan: Callee-preserved register has been modified!\n");
    exit(EXIT_FAILURE);
}

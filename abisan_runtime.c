#include <stdio.h> // for fprintf, stderr
#include <stdint.h> // for uint64_t
#include <stdlib.h> // for exit, EXIT_FAILURE

// Maybe should be packed, but will be fine as long as everything remains 8-byte
struct abisan_shadow_stack_frame {
    uint64_t retaddr;
    uint64_t rbx;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
};

#define SHADOW_STACK_SIZE (10)
struct abisan_shadow_stack_frame ABISAN_SHADOW_STACK_BASE[SHADOW_STACK_SIZE];
struct abisan_shadow_stack_frame *abisan_shadow_stack_pointer = ABISAN_SHADOW_STACK_BASE;

[[noreturn]] void abisan_fail_rbx(void) {
    fprintf(stderr, "ABISan: rbx clobbered!\n");
    exit(EXIT_FAILURE);
}

[[noreturn]] void abisan_fail_rbp(void) {
    fprintf(stderr, "ABISan: rbp clobbered!\n");
    exit(EXIT_FAILURE);
}

[[noreturn]] void abisan_fail_rsp(void) {
    fprintf(stderr, "ABISan: rsp clobbered!\n");
    exit(EXIT_FAILURE);
}

[[noreturn]] void abisan_fail_r12(void) {
    fprintf(stderr, "ABISan: r12 clobbered!\n");
    exit(EXIT_FAILURE);
}

[[noreturn]] void abisan_fail_r13(void) {
    fprintf(stderr, "ABISan: r13 clobbered!\n");
    exit(EXIT_FAILURE);
}

[[noreturn]] void abisan_fail_r14(void) {
    fprintf(stderr, "ABISan: r14 clobbered!\n");
    exit(EXIT_FAILURE);
}

[[noreturn]] void abisan_fail_r15(void) {
    fprintf(stderr, "ABISan: r15 clobbered!\n");
    exit(EXIT_FAILURE);
}

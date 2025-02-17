#include <stdio.h>  // for fprintf, stderr
#include <stdint.h> // for uint16_t
#include <inttypes.h> // for PRIx16
#include <stdlib.h> // for exit, EXIT_FAILURE

struct abisan_shadow_stack_frame {
    void *retaddr;
    void *rbx;
    void *rbp;
    void *rsp;
    void *r12;
    void *r13;
    void *r14;
    void *r15;
    void *instrumentation_retaddr;
    uint16_t x87cw;
    uint16_t fs;
} __attribute__((packed));

#define SHADOW_STACK_SIZE (10)
struct abisan_shadow_stack_frame ABISAN_SHADOW_STACK_BASE[SHADOW_STACK_SIZE];
struct abisan_shadow_stack_frame *abisan_shadow_stack_pointer =
    ABISAN_SHADOW_STACK_BASE;

[[noreturn]] void
abisan_fail(char const *const msg,
            struct abisan_shadow_stack_frame const *const frame) {
    fprintf(stderr,
            "ABISan: %s by the function at address %p, which was called at "
            "address %p.\n",
            msg, frame->instrumentation_retaddr, frame->retaddr);
    fprintf(stderr, "    Saved rbx: %p\n", frame->rbx);
    fprintf(stderr, "    Saved rbp: %p\n", frame->rbp);
    fprintf(stderr, "    Saved rsp: %p\n", frame->rsp);
    fprintf(stderr, "    Saved r12: %p\n", frame->r12);
    fprintf(stderr, "    Saved r13: %p\n", frame->r13);
    fprintf(stderr, "    Saved r14: %p\n", frame->r14);
    fprintf(stderr, "    Saved r15: %p\n", frame->r15);
    fprintf(stderr, "    Saved x87 control word: 0x%" PRIx16 "\n", frame->x87cw);
    fprintf(stderr, "    Saved fs: 0x%" PRIx16 "\n", frame->fs);
    exit(EXIT_FAILURE);
}

[[noreturn]] void
abisan_fail_rbx(struct abisan_shadow_stack_frame const *const frame) {
    abisan_fail("rbx clobbered", frame);
}

[[noreturn]] void
abisan_fail_rbp(struct abisan_shadow_stack_frame const *const frame) {
    abisan_fail("rbp clobbered", frame);
}

[[noreturn]] void
abisan_fail_rsp(struct abisan_shadow_stack_frame const *const frame) {
    abisan_fail("rsp clobbered", frame);
}

[[noreturn]] void
abisan_fail_r12(struct abisan_shadow_stack_frame const *const frame) {
    abisan_fail("r12 clobbered", frame);
}

[[noreturn]] void
abisan_fail_r13(struct abisan_shadow_stack_frame const *const frame) {
    abisan_fail("r12 clobbered", frame);
}

[[noreturn]] void
abisan_fail_r14(struct abisan_shadow_stack_frame const *const frame) {
    abisan_fail("r12 clobbered", frame);
}

[[noreturn]] void
abisan_fail_r15(struct abisan_shadow_stack_frame const *const frame) {
    abisan_fail("r12 clobbered", frame);
}

[[noreturn]] void
abisan_fail_x87cw(struct abisan_shadow_stack_frame const *const frame) {
    abisan_fail("x86 control word clobbered", frame);
}

[[noreturn]] void
abisan_fail_fs(struct abisan_shadow_stack_frame const *const frame) {
    abisan_fail("fs clobbered", frame);
}

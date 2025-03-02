#include <inttypes.h> // for PRIx16, PRIx64
#include <stdint.h>   // for uint16_t, uint64_t
#include <stdio.h>    // for fprintf, stderr
#include <stdlib.h>   // for exit, EXIT_FAILURE

struct abisan_shadow_stack_frame {
    void *retaddr;
    uint64_t rbx;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    void *instrumentation_retaddr;
    uint16_t x87cw;
    uint16_t fs;
    uint32_t mxcsr;
} __attribute__((packed));

#define SHADOW_STACK_SIZE (1000)
struct abisan_shadow_stack_frame ABISAN_SHADOW_STACK_BASE[SHADOW_STACK_SIZE];
struct abisan_shadow_stack_frame *abisan_shadow_stack_pointer =
    ABISAN_SHADOW_STACK_BASE;

struct taint_state {
    bool rax;
    bool rbx;
    bool rcx;
    bool rdx;
    bool rdi;
    bool rsi;
    bool rbp;
    bool r8;
    bool r9;
    bool r10;
    bool r11;
    bool r12;
    bool r13;
    bool r14;
    bool r15;
    // TODO: Track all the other registers
} __attribute__((packed));

struct taint_state abisan_taint_state = {
    .rax=0,
    .rbx=0,
    .rcx=0,
    .rdx=0,
    .rdi=0,
    .rsi=0,
    .rbp=0,
    .r8=0,
    .r9=0,
    .r10=0,
    .r11=0,
    .r12=0,
    .r13=0,
    .r14=0,
    .r15=0
};

[[noreturn]] void
abisan_fail_clobber(char const *const clobbered_register,
            uint64_t const clobbered_value,
            struct abisan_shadow_stack_frame const *const frame) {
    fprintf(stderr,
            "ABISan: %s clobbered with 0x%" PRIx64
            " by the function at address %p, which was called at "
            "address %p.\n",
            clobbered_register, clobbered_value, frame->instrumentation_retaddr,
            frame->retaddr);
    fprintf(stderr, "    Saved rbx: 0x%" PRIx64 "\n", frame->rbx);
    fprintf(stderr, "    Saved rbp: 0x%" PRIx64 "\n", frame->rbp);
    fprintf(stderr, "    Saved rsp: 0x%" PRIx64 "\n", frame->rsp);
    fprintf(stderr, "    Saved r12: 0x%" PRIx64 "\n", frame->r12);
    fprintf(stderr, "    Saved r13: 0x%" PRIx64 "\n", frame->r13);
    fprintf(stderr, "    Saved r14: 0x%" PRIx64 "\n", frame->r14);
    fprintf(stderr, "    Saved r15: 0x%" PRIx64 "\n", frame->r15);
    fprintf(stderr, "    Saved x87 control word: 0x%" PRIx16 "\n",
            frame->x87cw);
    fprintf(stderr, "    Saved fs: 0x%" PRIx16 "\n", frame->fs);
    exit(EXIT_FAILURE);
}

[[noreturn]] void
abisan_fail_rbx(struct abisan_shadow_stack_frame const *const frame,
                uint64_t rbx) {
    abisan_fail_clobber("rbx", rbx, frame);
}

[[noreturn]] void
abisan_fail_rbp(struct abisan_shadow_stack_frame const *const frame,
                uint64_t rbp) {
    abisan_fail_clobber("rbp", rbp, frame);
}

[[noreturn]] void
abisan_fail_rsp(struct abisan_shadow_stack_frame const *const frame,
                uint64_t rsp) {
    abisan_fail_clobber("rsp", rsp, frame);
}

[[noreturn]] void
abisan_fail_r12(struct abisan_shadow_stack_frame const *const frame,
                uint64_t r12) {
    abisan_fail_clobber("r12", r12, frame);
}

[[noreturn]] void
abisan_fail_r13(struct abisan_shadow_stack_frame const *const frame,
                uint64_t r13) {
    abisan_fail_clobber("r13", r13, frame);
}

[[noreturn]] void
abisan_fail_r14(struct abisan_shadow_stack_frame const *const frame,
                uint64_t r14) {
    abisan_fail_clobber("r14", r14, frame);
}

[[noreturn]] void
abisan_fail_r15(struct abisan_shadow_stack_frame const *const frame,
                uint64_t r15) {
    abisan_fail_clobber("r15", r15, frame);
}

[[noreturn]] void
abisan_fail_x87cw(struct abisan_shadow_stack_frame const *const frame,
                  uint16_t x87cw) {
    abisan_fail_clobber("x87 control word", x87cw, frame);
}

[[noreturn]] void
abisan_fail_fs(struct abisan_shadow_stack_frame const *const frame,
               uint16_t fs) {
    abisan_fail_clobber("fs", fs, frame);
}

[[noreturn]] void
abisan_fail_mxcsr(struct abisan_shadow_stack_frame const *const frame,
               uint16_t mxcsr) {
    abisan_fail_clobber("mxcsr control bits", mxcsr, frame);
}

[[noreturn]] void
abisan_fail_mov_below_rsp(void) {
    fprintf(stderr, "You accessed below rsp! (This might be fine though, if you're using the red zone)\n");
    exit(EXIT_FAILURE);
}

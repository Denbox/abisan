#include <inttypes.h> // for PRIx16, PRIx64
#include <stdint.h>   // for uint8_t, uint16_t, uint64_t
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
#undef SHADOW_STACK_SIZE
struct abisan_shadow_stack_frame *abisan_shadow_stack_pointer =
    ABISAN_SHADOW_STACK_BASE;

struct taint_state {
    uint8_t rax;
    uint8_t rbx;
    uint8_t rcx;
    uint8_t rdx;
    uint8_t rdi;
    uint8_t rsi;
    uint8_t r8;
    uint8_t r9;
    uint8_t r10;
    uint8_t r11;
    uint8_t r12;
    uint8_t r13;
    uint8_t r14;
    uint8_t r15;
    uint8_t rbp;
    uint8_t eflags;
    // TODO: Track all the other registers
} __attribute__((packed));

struct taint_state abisan_taint_state = {.rax = 0xff,
                                         .rbx = 0xff,
                                         .rcx = 0,
                                         .rdx = 0,
                                         .rdi = 0,
                                         .rsi = 0,
                                         .r8 = 0,
                                         .r9 = 0,
                                         .r10 = 0xff,
                                         .r11 = 0xff,
                                         .r12 = 0xff,
                                         .r13 = 0xff,
                                         .r14 = 0xff,
                                         .r15 = 0xff,
                                         .rbp = 0xff,
                                         .eflags = 0};

#define ABISAN_ERROR_START "\x1b[0;31mABISanitizer: "

[[noreturn]] void
abisan_fail_clobber(char const *const clobbered_register,
                    uint64_t const clobbered_value,
                    struct abisan_shadow_stack_frame const *const frame) {
    fprintf(stderr,
            ABISAN_ERROR_START
            "%s clobbered with 0x%" PRIx64
            " by the function at address %p, which was called at "
            "address %p.\x1b[0m\n",
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

[[noreturn]] void abisan_fail_mov_below_rsp(void) {
    fprintf(stderr,
            ABISAN_ERROR_START "You accessed below the redzone!\x1b[0m\n");
    exit(EXIT_FAILURE);
}

[[noreturn]] void abisan_fail_taint(char const *const r) {
    fprintf(stderr, ABISAN_ERROR_START "You accessed a tainted %s.\x1b[0m\n",
            r);
    exit(EXIT_FAILURE);
}

[[noreturn]] void abisan_fail_taint_rax(void) {
    abisan_fail_taint("rax");
}

[[noreturn]] void abisan_fail_taint_eax(void) {
    abisan_fail_taint("eax");
}

[[noreturn]] void abisan_fail_taint_ax(void) {
    abisan_fail_taint("ax");
}

[[noreturn]] void abisan_fail_taint_ah(void) {
    abisan_fail_taint("ah");
}

[[noreturn]] void abisan_fail_taint_al(void) {
    abisan_fail_taint("al");
}
[[noreturn]] void abisan_fail_taint_rbx(void) {
    abisan_fail_taint("rbx");
}

[[noreturn]] void abisan_fail_taint_ebx(void) {
    abisan_fail_taint("ebx");
}

[[noreturn]] void abisan_fail_taint_bx(void) {
    abisan_fail_taint("bx");
}

[[noreturn]] void abisan_fail_taint_bh(void) {
    abisan_fail_taint("bh");
}

[[noreturn]] void abisan_fail_taint_bl(void) {
    abisan_fail_taint("bl");
}
[[noreturn]] void abisan_fail_taint_rcx(void) {
    abisan_fail_taint("rcx");
}

[[noreturn]] void abisan_fail_taint_ecx(void) {
    abisan_fail_taint("ecx");
}

[[noreturn]] void abisan_fail_taint_cx(void) {
    abisan_fail_taint("cx");
}

[[noreturn]] void abisan_fail_taint_ch(void) {
    abisan_fail_taint("ch");
}

[[noreturn]] void abisan_fail_taint_cl(void) {
    abisan_fail_taint("cl");
}
[[noreturn]] void abisan_fail_taint_rdx(void) {
    abisan_fail_taint("rdx");
}

[[noreturn]] void abisan_fail_taint_edx(void) {
    abisan_fail_taint("edx");
}

[[noreturn]] void abisan_fail_taint_dx(void) {
    abisan_fail_taint("dx");
}

[[noreturn]] void abisan_fail_taint_dh(void) {
    abisan_fail_taint("dh");
}

[[noreturn]] void abisan_fail_taint_dl(void) {
    abisan_fail_taint("dl");
}

[[noreturn]] void abisan_fail_taint_rdi(void) {
    abisan_fail_taint("rdi");
}

[[noreturn]] void abisan_fail_taint_edi(void) {
    abisan_fail_taint("edi");
}

[[noreturn]] void abisan_fail_taint_di(void) {
    abisan_fail_taint("di");
}

[[noreturn]] void abisan_fail_taint_dil(void) {
    abisan_fail_taint("dil");
}

[[noreturn]] void abisan_fail_taint_rsi(void) {
    abisan_fail_taint("rsi");
}

[[noreturn]] void abisan_fail_taint_esi(void) {
    abisan_fail_taint("esi");
}

[[noreturn]] void abisan_fail_taint_si(void) {
    abisan_fail_taint("si");
}

[[noreturn]] void abisan_fail_taint_sil(void) {
    abisan_fail_taint("sil");
}

[[noreturn]] void abisan_fail_taint_r8(void) {
    abisan_fail_taint("r8");
}

[[noreturn]] void abisan_fail_taint_r8d(void) {
    abisan_fail_taint("r8d");
}

[[noreturn]] void abisan_fail_taint_r8w(void) {
    abisan_fail_taint("r8w");
}

[[noreturn]] void abisan_fail_taint_r8b(void) {
    abisan_fail_taint("r8b");
}

[[noreturn]] void abisan_fail_taint_r9(void) {
    abisan_fail_taint("r9");
}

[[noreturn]] void abisan_fail_taint_r9d(void) {
    abisan_fail_taint("r9d");
}

[[noreturn]] void abisan_fail_taint_r9w(void) {
    abisan_fail_taint("r9w");
}

[[noreturn]] void abisan_fail_taint_r9b(void) {
    abisan_fail_taint("r9b");
}

[[noreturn]] void abisan_fail_taint_r10(void) {
    abisan_fail_taint("r10");
}

[[noreturn]] void abisan_fail_taint_r10d(void) {
    abisan_fail_taint("r10d");
}

[[noreturn]] void abisan_fail_taint_r10w(void) {
    abisan_fail_taint("r10w");
}

[[noreturn]] void abisan_fail_taint_r10b(void) {
    abisan_fail_taint("r10b");
}

[[noreturn]] void abisan_fail_taint_r11(void) {
    abisan_fail_taint("r11");
}

[[noreturn]] void abisan_fail_taint_r11d(void) {
    abisan_fail_taint("r11d");
}

[[noreturn]] void abisan_fail_taint_r11w(void) {
    abisan_fail_taint("r11w");
}

[[noreturn]] void abisan_fail_taint_r11b(void) {
    abisan_fail_taint("r11b");
}

[[noreturn]] void abisan_fail_taint_r12(void) {
    abisan_fail_taint("r12");
}

[[noreturn]] void abisan_fail_taint_r12d(void) {
    abisan_fail_taint("r12d");
}

[[noreturn]] void abisan_fail_taint_r12w(void) {
    abisan_fail_taint("r12w");
}

[[noreturn]] void abisan_fail_taint_r12b(void) {
    abisan_fail_taint("r12b");
}

[[noreturn]] void abisan_fail_taint_r13(void) {
    abisan_fail_taint("r13");
}

[[noreturn]] void abisan_fail_taint_r13d(void) {
    abisan_fail_taint("r13d");
}

[[noreturn]] void abisan_fail_taint_r13w(void) {
    abisan_fail_taint("r13w");
}

[[noreturn]] void abisan_fail_taint_r13b(void) {
    abisan_fail_taint("r13b");
}

[[noreturn]] void abisan_fail_taint_r14(void) {
    abisan_fail_taint("r14");
}

[[noreturn]] void abisan_fail_taint_r14d(void) {
    abisan_fail_taint("r14d");
}

[[noreturn]] void abisan_fail_taint_r14w(void) {
    abisan_fail_taint("r14w");
}

[[noreturn]] void abisan_fail_taint_r14b(void) {
    abisan_fail_taint("r14b");
}

[[noreturn]] void abisan_fail_taint_r15(void) {
    abisan_fail_taint("r15");
}

[[noreturn]] void abisan_fail_taint_r15d(void) {
    abisan_fail_taint("r15d");
}

[[noreturn]] void abisan_fail_taint_r15w(void) {
    abisan_fail_taint("r15w");
}

[[noreturn]] void abisan_fail_taint_r15b(void) {
    abisan_fail_taint("r15b");
}

[[noreturn]] void abisan_fail_taint_rbp(void) {
    abisan_fail_taint("rbp");
}

[[noreturn]] void abisan_fail_taint_ebp(void) {
    abisan_fail_taint("ebp");
}

[[noreturn]] void abisan_fail_taint_bp(void) {
    abisan_fail_taint("bp");
}

[[noreturn]] void abisan_fail_taint_bpl(void) {
    abisan_fail_taint("bpl");
}

[[noreturn]] void abisan_fail_taint_rflags(void) {
    abisan_fail_taint("eflags");
}

[[noreturn]] void abisan_fail_taint_zmm0(void) {
    abisan_fail_taint("zmm0");
}

[[noreturn]] void abisan_fail_taint_ymm0(void) {
    abisan_fail_taint("ymm0");
}

[[noreturn]] void abisan_fail_taint_xmm0(void) {
    abisan_fail_taint("xmm0");
}

[[noreturn]] void abisan_fail_taint_zmm1(void) {
    abisan_fail_taint("zmm1");
}

[[noreturn]] void abisan_fail_taint_ymm1(void) {
    abisan_fail_taint("ymm1");
}

[[noreturn]] void abisan_fail_taint_xmm1(void) {
    abisan_fail_taint("xmm1");
}

[[noreturn]] void abisan_fail_taint_zmm2(void) {
    abisan_fail_taint("zmm2");
}

[[noreturn]] void abisan_fail_taint_ymm2(void) {
    abisan_fail_taint("ymm2");
}

[[noreturn]] void abisan_fail_taint_xmm2(void) {
    abisan_fail_taint("xmm2");
}

[[noreturn]] void abisan_fail_taint_zmm3(void) {
    abisan_fail_taint("zmm3");
}

[[noreturn]] void abisan_fail_taint_ymm3(void) {
    abisan_fail_taint("ymm3");
}

[[noreturn]] void abisan_fail_taint_xmm3(void) {
    abisan_fail_taint("xmm3");
}

[[noreturn]] void abisan_fail_taint_zmm4(void) {
    abisan_fail_taint("zmm4");
}

[[noreturn]] void abisan_fail_taint_ymm4(void) {
    abisan_fail_taint("ymm4");
}

[[noreturn]] void abisan_fail_taint_xmm4(void) {
    abisan_fail_taint("xmm4");
}

[[noreturn]] void abisan_fail_taint_zmm5(void) {
    abisan_fail_taint("zmm5");
}

[[noreturn]] void abisan_fail_taint_ymm5(void) {
    abisan_fail_taint("ymm5");
}

[[noreturn]] void abisan_fail_taint_xmm5(void) {
    abisan_fail_taint("xmm5");
}

[[noreturn]] void abisan_fail_taint_zmm6(void) {
    abisan_fail_taint("zmm6");
}

[[noreturn]] void abisan_fail_taint_ymm6(void) {
    abisan_fail_taint("ymm6");
}

[[noreturn]] void abisan_fail_taint_xmm6(void) {
    abisan_fail_taint("xmm6");
}

[[noreturn]] void abisan_fail_taint_zmm7(void) {
    abisan_fail_taint("zmm7");
}

[[noreturn]] void abisan_fail_taint_ymm7(void) {
    abisan_fail_taint("ymm7");
}

[[noreturn]] void abisan_fail_taint_xmm7(void) {
    abisan_fail_taint("xmm7");
}

[[noreturn]] void abisan_fail_taint_zmm8(void) {
    abisan_fail_taint("zmm8");
}

[[noreturn]] void abisan_fail_taint_ymm8(void) {
    abisan_fail_taint("ymm8");
}

[[noreturn]] void abisan_fail_taint_xmm8(void) {
    abisan_fail_taint("xmm8");
}

[[noreturn]] void abisan_fail_taint_zmm9(void) {
    abisan_fail_taint("zmm9");
}

[[noreturn]] void abisan_fail_taint_ymm9(void) {
    abisan_fail_taint("ymm9");
}

[[noreturn]] void abisan_fail_taint_xmm9(void) {
    abisan_fail_taint("xmm9");
}

[[noreturn]] void abisan_fail_taint_zmm10(void) {
    abisan_fail_taint("zmm10");
}

[[noreturn]] void abisan_fail_taint_ymm10(void) {
    abisan_fail_taint("ymm10");
}

[[noreturn]] void abisan_fail_taint_xmm10(void) {
    abisan_fail_taint("xmm10");
}

[[noreturn]] void abisan_fail_taint_zmm11(void) {
    abisan_fail_taint("zmm11");
}

[[noreturn]] void abisan_fail_taint_ymm11(void) {
    abisan_fail_taint("ymm11");
}

[[noreturn]] void abisan_fail_taint_xmm11(void) {
    abisan_fail_taint("xmm11");
}

[[noreturn]] void abisan_fail_taint_zmm12(void) {
    abisan_fail_taint("zmm12");
}

[[noreturn]] void abisan_fail_taint_ymm12(void) {
    abisan_fail_taint("ymm12");
}

[[noreturn]] void abisan_fail_taint_xmm12(void) {
    abisan_fail_taint("xmm12");
}

[[noreturn]] void abisan_fail_taint_zmm13(void) {
    abisan_fail_taint("zmm13");
}

[[noreturn]] void abisan_fail_taint_ymm13(void) {
    abisan_fail_taint("ymm13");
}

[[noreturn]] void abisan_fail_taint_xmm13(void) {
    abisan_fail_taint("xmm13");
}

[[noreturn]] void abisan_fail_taint_zmm14(void) {
    abisan_fail_taint("zmm14");
}

[[noreturn]] void abisan_fail_taint_ymm14(void) {
    abisan_fail_taint("ymm14");
}

[[noreturn]] void abisan_fail_taint_xmm14(void) {
    abisan_fail_taint("xmm14");
}

[[noreturn]] void abisan_fail_taint_zmm15(void) {
    abisan_fail_taint("zmm15");
}

[[noreturn]] void abisan_fail_taint_ymm15(void) {
    abisan_fail_taint("ymm15");
}

[[noreturn]] void abisan_fail_taint_xmm15(void) {
    abisan_fail_taint("xmm15");
}

[[noreturn]] void abisan_fail_taint_zmm16(void) {
    abisan_fail_taint("zmm16");
}

[[noreturn]] void abisan_fail_taint_ymm16(void) {
    abisan_fail_taint("ymm16");
}

[[noreturn]] void abisan_fail_taint_xmm16(void) {
    abisan_fail_taint("xmm16");
}

[[noreturn]] void abisan_fail_taint_zmm17(void) {
    abisan_fail_taint("zmm17");
}

[[noreturn]] void abisan_fail_taint_ymm17(void) {
    abisan_fail_taint("ymm17");
}

[[noreturn]] void abisan_fail_taint_xmm17(void) {
    abisan_fail_taint("xmm17");
}

[[noreturn]] void abisan_fail_taint_zmm18(void) {
    abisan_fail_taint("zmm18");
}

[[noreturn]] void abisan_fail_taint_ymm187(void) {
    abisan_fail_taint("ymm18");
}

[[noreturn]] void abisan_fail_taint_xmm18(void) {
    abisan_fail_taint("xmm18");
}

[[noreturn]] void abisan_fail_taint_zmm19(void) {
    abisan_fail_taint("zmm19");
}

[[noreturn]] void abisan_fail_taint_ymm19(void) {
    abisan_fail_taint("ymm19");
}

[[noreturn]] void abisan_fail_taint_xmm19(void) {
    abisan_fail_taint("xmm19");
}

[[noreturn]] void abisan_fail_taint_zmm20(void) {
    abisan_fail_taint("zmm20");
}

[[noreturn]] void abisan_fail_taint_ymm20(void) {
    abisan_fail_taint("ymm20");
}

[[noreturn]] void abisan_fail_taint_xmm20(void) {
    abisan_fail_taint("xmm20");
}

[[noreturn]] void abisan_fail_taint_zmm21(void) {
    abisan_fail_taint("zmm21");
}

[[noreturn]] void abisan_fail_taint_ymm21(void) {
    abisan_fail_taint("ymm21");
}

[[noreturn]] void abisan_fail_taint_xmm21(void) {
    abisan_fail_taint("xmm21");
}

[[noreturn]] void abisan_fail_taint_zmm22(void) {
    abisan_fail_taint("zmm22");
}

[[noreturn]] void abisan_fail_taint_ymm22(void) {
    abisan_fail_taint("ymm22");
}

[[noreturn]] void abisan_fail_taint_xmm22(void) {
    abisan_fail_taint("xmm22");
}

[[noreturn]] void abisan_fail_taint_zmm23(void) {
    abisan_fail_taint("zmm23");
}

[[noreturn]] void abisan_fail_taint_ymm23(void) {
    abisan_fail_taint("ymm23");
}

[[noreturn]] void abisan_fail_taint_xmm23(void) {
    abisan_fail_taint("xmm23");
}

[[noreturn]] void abisan_fail_taint_zmm24(void) {
    abisan_fail_taint("zmm24");
}

[[noreturn]] void abisan_fail_taint_ymm24(void) {
    abisan_fail_taint("ymm24");
}

[[noreturn]] void abisan_fail_taint_xmm24(void) {
    abisan_fail_taint("xmm24");
}

[[noreturn]] void abisan_fail_taint_zmm25(void) {
    abisan_fail_taint("zmm25");
}

[[noreturn]] void abisan_fail_taint_ymm25(void) {
    abisan_fail_taint("ymm25");
}

[[noreturn]] void abisan_fail_taint_xmm25(void) {
    abisan_fail_taint("xmm25");
}

[[noreturn]] void abisan_fail_taint_zmm26(void) {
    abisan_fail_taint("zmm26");
}

[[noreturn]] void abisan_fail_taint_ymm26(void) {
    abisan_fail_taint("ymm26");
}

[[noreturn]] void abisan_fail_taint_xmm26(void) {
    abisan_fail_taint("xmm26");
}

[[noreturn]] void abisan_fail_taint_zmm27(void) {
    abisan_fail_taint("zmm27");
}

[[noreturn]] void abisan_fail_taint_ymm27(void) {
    abisan_fail_taint("ymm27");
}

[[noreturn]] void abisan_fail_taint_xmm27(void) {
    abisan_fail_taint("xmm27");
}

[[noreturn]] void abisan_fail_taint_zmm28(void) {
    abisan_fail_taint("zmm28");
}

[[noreturn]] void abisan_fail_taint_ymm28(void) {
    abisan_fail_taint("ymm28");
}

[[noreturn]] void abisan_fail_taint_xmm28(void) {
    abisan_fail_taint("xmm28");
}

[[noreturn]] void abisan_fail_taint_zmm29(void) {
    abisan_fail_taint("zmm29");
}

[[noreturn]] void abisan_fail_taint_ymm29(void) {
    abisan_fail_taint("ymm29");
}

[[noreturn]] void abisan_fail_taint_xmm29(void) {
    abisan_fail_taint("xmm29");
}

[[noreturn]] void abisan_fail_taint_zmm30(void) {
    abisan_fail_taint("zmm30");
}

[[noreturn]] void abisan_fail_taint_ymm30(void) {
    abisan_fail_taint("ymm30");
}

[[noreturn]] void abisan_fail_taint_xmm30(void) {
    abisan_fail_taint("xmm30");
}

[[noreturn]] void abisan_fail_taint_zmm31(void) {
    abisan_fail_taint("zmm31");
}

[[noreturn]] void abisan_fail_taint_ymm31(void) {
    abisan_fail_taint("ymm31");
}

[[noreturn]] void abisan_fail_taint_xmm31(void) {
    abisan_fail_taint("xmm31");
}

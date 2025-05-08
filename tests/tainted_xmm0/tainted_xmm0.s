.intel_syntax noprefix

.globl tainted_xmm0
tainted_xmm0:
    vmovdqu xmm1, xmm0
    ret

.intel_syntax noprefix

.globl tainted_ymm0
tainted_ymm0:
    vmovdqu ymm1, ymm0
    ret

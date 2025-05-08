.intel_syntax noprefix

.globl tainted_zmm0
tainted_zmm0:
    vmovaps zmm1, zmm0
    ret

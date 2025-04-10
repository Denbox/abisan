.intel_syntax noprefix

.globl tainted_bh
tainted_bh:
    mov ah, bh
    ret

.intel_syntax noprefix

.globl f
f:
    ret

.globl tainted_bpl
tainted_bpl:
    call f
    mov al, bpl
    ret

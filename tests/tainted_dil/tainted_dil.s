.intel_syntax noprefix

.globl f
f:
    ret

.globl tainted_dil
tainted_dil:
    call f
    mov al, dil
    ret

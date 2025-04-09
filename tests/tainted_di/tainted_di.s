.intel_syntax noprefix

.globl f
f:
    ret

.globl tainted_di
tainted_di:
    call f
    mov ax, di
    ret

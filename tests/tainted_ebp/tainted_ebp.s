.intel_syntax noprefix

.globl f
f:
    ret

.globl tainted_ebp
tainted_ebp:
    call f
    mov eax, ebp
    ret

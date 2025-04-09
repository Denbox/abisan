.intel_syntax noprefix

.globl f
f:
    ret

.globl tainted_edi
tainted_edi:
    call f
    mov eax, edi
    ret

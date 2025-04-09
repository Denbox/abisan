.intel_syntax noprefix

.globl f
f:
    ret

.globl tainted_rdi_untainted_dil
tainted_rdi_untainted_dil:
    call f
    mov dil, al
    mov rax, rdi
    ret

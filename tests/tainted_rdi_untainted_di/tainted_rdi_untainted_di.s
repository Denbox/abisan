.intel_syntax noprefix

.globl f
f:
    ret

.globl tainted_rdi_untainted_di
tainted_rdi_untainted_di:
    call f
    mov di, ax
    mov rax, rdi
    ret

.intel_syntax noprefix

.globl f
f:
    ret

.globl tainted_rdi
tainted_rdi:
    call f
    mov rax, rdi
    ret

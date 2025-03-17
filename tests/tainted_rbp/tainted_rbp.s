.intel_syntax noprefix

.globl tainted_rbp
tainted_rbp:
    mov rax, rbp
    ret

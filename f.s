.intel_syntax noprefix

.globl f
f:
    inc rbx # Violates the ABI
    add rdi, rsi
    mov rax, rdi
    ret

.intel_syntax noprefix

.globl f
f:
    # inc rbx # Uncomment me to see what happens when you clobber rbx
    add rdi, rsi
    mov rax, rdi
    ret

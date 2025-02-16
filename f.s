.intel_syntax noprefix

# uint32_t f(uint32_t, uint32_t)
.globl f
f:
    call abisan_function_entry
    add rdi, rsi
    mov rax, rdi
    ret

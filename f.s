.intel_syntax noprefix

# uint32_t f(uint32_t, uint32_t)
.globl f
f:
    # call abisan_f_entry_instrumentation # e8 57 00 00 00
    # nop                                 # 90
    xor rbx, rbx
    add rbx, rdi
    add rbx, rsi
    mov rax, rbx
    ret


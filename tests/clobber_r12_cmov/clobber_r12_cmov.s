.intel_syntax noprefix

.globl clobber_r12_cmov
clobber_r12_cmov:
    push r11
    xor r11, r11
    cmp r11, 0
    cmove r12, r11
    pop r11
    ret

.intel_syntax noprefix

.globl clobber_r12w_cmov
clobber_r12w_cmov:
	push r11
    xor r11, r11
    cmp r11, 0
    cmove r12w, r11w
	pop r11
    ret

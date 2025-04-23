.globl clobber_r12_cmov_att
clobber_r12_cmov_att:
	push %r11
    xor %r11, %r11
    cmp $0, %r11
    cmove %r11, %r12
	pop %r11
    ret

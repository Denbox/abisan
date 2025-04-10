.intel_syntax noprefix

.globl clobber_bh
clobber_bh:
    mov bh, 0x10
    ret

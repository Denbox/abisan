.intel_syntax noprefix

.globl clobber_rsp
clobber_rsp:
    pop rax # Get retaddr
    pop r11 # Get 7th arg
    push rax # Push retaddr
    ret


.globl f
f:
    ret

.globl tainted_rdi_att
tainted_rdi_att:
    call f
    mov %rdi, %rax
    ret

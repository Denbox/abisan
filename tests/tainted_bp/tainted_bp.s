.intel_syntax noprefix

.globl f
f:
    ret

.globl tainted_bp
tainted_bp:
    call f
    mov ax, bp                   ;
    ret

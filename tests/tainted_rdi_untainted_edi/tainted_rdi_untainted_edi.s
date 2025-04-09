.intel_syntax noprefix

.globl f
f:
    ret

.globl tainted_rdi_untainted_edi
tainted_rdi_untainted_edi:
    call f
    mov edi, eax # untaint edi
    mov rax, rdi # read from tainted rdi
    ret

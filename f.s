.intel_syntax noprefix

.globl g
g:
    # mov rdx, QWORD PTR [rsp - 0x10] # Violates the ABI
    ret

.globl f
f:
    # inc rbx # Violates the ABI
    add rdi, rsi
    push rdi
    call g
    pop rdi
    mov rax, rdi
    ret

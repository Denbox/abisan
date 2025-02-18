.intel_syntax noprefix

.globl g
g:
    mov rdi, 1
    cmp rdi, 0
    cmovbe rdx, QWORD PTR [rsp - 0x10] # Does not violate the ABI, because condition is false
    mov rdx, QWORD PTR [rsp - 0x10] # Violates the ABI
    ret

.globl f
f:
    inc rbx # Violates the ABI
    add rdi, rsi
    push rdi
    # call g
    pop rdi
    mov rax, rdi
    ret

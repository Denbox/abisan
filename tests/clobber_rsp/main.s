.intel_syntax noprefix

.globl main
main:
    mov rdi, 0
    mov rsi, 1
    mov rdx, 2
    mov rcx, 3
    mov r8, 4
    mov r9, 5
    mov rax, 6
    push rax
    call clobber_rsp
    ret

.globl control_att
control_att:
    push %rbp
    mov %rsp, %rbp
    sub $0x10, %rsp

    # TODO: write to zmm, read from sub regs. We must first support more vector instructions

    # Mov into stack
    mov %r11, -0x10(%rbp)

    # Add up the first 7 arguments into %rax
    xor %rax, %rax
    add %rdi, %rax
    add %rsi, %rax
    add %rdx, %rax
    add %rcx, %rax
    add %r8, %rax
    add %r9, %rax
    add 0x10(%rbp), %rax

    # mov into the heap
    push %rax
    mov $1, %rdi
    call malloc
    movb $0, (%rax)
    mov %rax, %rdi
    call free
    pop %rax

    # cmov from the heap
    push %rax
    mov $4, %rdi
    call malloc
    movl $0xdeadbeef, (%rax)
    mov $1, %rdi
    cmp $0, %rdi
    cmova (%rax), %edi
    mov %rax, %rdi
    call free
    pop %rax

    # Write to volatile 64bit reg, read from its sub-regs
    push %rax
    mov $0x12345678, %r11
    mov %r11b , %al # Low 8 bits
    mov %r11w , %ax # Low 16 bits
    mov %r11d , %eax # low 32 bits
    mov %r11 , %rax # All 64 bits
    pop %rax

    # Zero all volatile registers
    xor %rdi, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    xor %rcx, %rcx
    xor %r8, %r8
    xor %r9, %r9
    xor %r10, %r10
    xor %r11, %r11
    xor %r11, %r11

    # Mov from above the frame
    mov 0x10(%rbp), %rcx

    # Mov from red zone
    mov -0x10(%rsp), %rcx

    add $0x10, %rsp
    pop %rbp
    ret

.globl control_access_below_red_zone_att
control_access_below_red_zone_att:
    # This assumes that the redzone is enabled. If it is disabled, abisan will throw an error
    # Zero rax
    xor %rax, %rax
   

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

    # Zero the red zone
    movq %rcx, -0x08(%rsp) 
    movq %rcx, -0x10(%rsp)
    movq %rcx, -0x18(%rsp)
    movq %rcx, -0x20(%rsp)
    movq %rcx, -0x28(%rsp)
    movq %rcx, -0x30(%rsp)
    movq %rcx, -0x38(%rsp)
    movq %rcx, -0x40(%rsp)
    movq %rcx, -0x48(%rsp)
    movq %rcx, -0x50(%rsp)
    movq %rcx, -0x58(%rsp)
    movq %rcx, -0x60(%rsp)
    movq %rcx, -0x68(%rsp)
    movq %rcx, -0x70(%rsp)
    movq %rcx, -0x78(%rsp)
    movq %rcx, -0x80(%rsp)

    # Conditional mov from below the red zone with a false condition
    mov $1, %rdi
    cmp $0, %rdi
    cmovbe -0x88(%rsp), %rcx

    # Conditional mov in the red zone with a true condition
    cmova -0x80(%rsp), %rcx

    ret

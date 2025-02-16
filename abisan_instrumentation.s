.intel_syntax noprefix

.set SHADOW_STACK_FRAME_SIZE, 72 # XXX: Make sure this stays in sync with sizeof(struct abisan_shadow_stack_frame)
.set FRAME_RETADDR, 0x00
.set FRAME_RBX,     0x08
.set FRAME_RBP,     0x10
.set FRAME_RSP,     0x18
.set FRAME_R12,     0x20
.set FRAME_R13,     0x28
.set FRAME_R14,     0x30
.set FRAME_R15,     0x38
.set INSTRUMENTATION_RETADDR, 0x40

.extern abisan_shadow_stack_pointer

.globl abisan_function_entry
abisan_function_entry:
    mov r11, offset abisan_shadow_stack_pointer[rip]

    # Save stuff into the frame
    mov QWORD PTR [r11 + FRAME_RBX], rbx
    mov QWORD PTR [r11 + FRAME_RBP], rbp
    add rsp, 0x8
    mov QWORD PTR [r11 + FRAME_RSP], rsp
    sub rsp, 0x8
    mov QWORD PTR [r11 + FRAME_R12], r12
    mov QWORD PTR [r11 + FRAME_R13], r13
    mov QWORD PTR [r11 + FRAME_R14], r14
    mov QWORD PTR [r11 + FRAME_R15], r15

    # Save calling functions' return address into the frame
    mov rbx, QWORD PTR [rsp + 0x8]
    mov QWORD PTR [r11 + FRAME_RETADDR], rbx

    # Save our return address into the frame (used for debugging purposes only)
    mov rbx, QWORD PTR [rsp]
    mov QWORD PTR [r11 + INSTRUMENTATION_RETADDR], rbx

    # Replace the return address on the stack with abisan_function_exit
    lea rbx, offset abisan_function_exit[rip]
    mov QWORD PTR [rsp + 0x8], rbx

    # Update abisan_shadow_stack_pointer
    mov rbx, QWORD PTR offset abisan_shadow_stack_pointer[rip]
    add rbx, SHADOW_STACK_FRAME_SIZE
    mov QWORD PTR offset abisan_shadow_stack_pointer[rip], rbx

    # Put rbx back the way it was
    mov rbx, QWORD PTR [r11 + FRAME_RBX]
    ret

.globl abisan_function_exit
abisan_function_exit:
    sub rsp, 0x8 # To make up for the fact that this is returned into

    mov rdi, offset abisan_shadow_stack_pointer[rip]
    sub rdi, SHADOW_STACK_FRAME_SIZE
    mov QWORD PTR offset abisan_shadow_stack_pointer[rip], rdi

    cmp rbx, QWORD PTR [rdi + FRAME_RBX]
    jne abisan_fail_rbx
    cmp rbp, QWORD PTR [rdi + FRAME_RBP]
    jne abisan_fail_rbp
    cmp rsp, QWORD PTR [rdi + FRAME_RSP]
    jne abisan_fail_rsp
    cmp r12, QWORD PTR [rdi + FRAME_R12]
    jne abisan_fail_r12
    cmp r13, QWORD PTR [rdi + FRAME_R13]
    jne abisan_fail_r13
    cmp r14, QWORD PTR [rdi + FRAME_R14]
    jne abisan_fail_r14
    cmp r15, QWORD PTR [rdi + FRAME_R15]
    jne abisan_fail_r15

    # Put the original return address back in place
    mov rdi, QWORD PTR [rdi + FRAME_RETADDR]
    mov [rsp], rdi
    ret

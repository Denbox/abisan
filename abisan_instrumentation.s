.intel_syntax noprefix

.set ABISAN_SHADOW_STACK_FRAME_SIZE, 32 # XXX: Make sure this stays in sync with the size of an abisan stack frame

.extern abisan_shadow_stack_pointer

.globl abisan_function_entry
abisan_function_entry:
    mov r11, offset abisan_shadow_stack_pointer[rip]

    # Save rbx, rbp, and rsp into the frame
    mov QWORD PTR [r11 + 0x0], rbx
    mov QWORD PTR [r11 + 0x8], rbp

    add rsp, 8
    mov QWORD PTR [r11 + 0x10], rsp
    sub rsp, 8

    # Save the return address into the frame
    mov rbx, QWORD PTR [rsp + 0x8]
    mov QWORD PTR [r11 + 0x18], rbx

    # Replace the return address on the stack with abisan_function_exit
    lea rbx, offset abisan_function_exit[rip]
    mov QWORD PTR [rsp + 0x8], rbx

    # Update abisan_shadow_stack_pointer
    mov rbx, QWORD PTR offset abisan_shadow_stack_pointer[rip]
    add rbx, ABISAN_SHADOW_STACK_FRAME_SIZE
    mov QWORD PTR offset abisan_shadow_stack_pointer[rip], rbx

    # Put rbx back the way it was
    mov rbx, QWORD PTR [r11]
    ret

.globl abisan_function_exit
abisan_function_exit:
    sub rsp, 0x8 # To make up for the fact that this is returned into

    mov r11, offset abisan_shadow_stack_pointer[rip]
    sub r11, ABISAN_SHADOW_STACK_FRAME_SIZE

    cmp rbx, QWORD PTR [r11 + 0x0]
    jne abisan_fail
    cmp rbp, QWORD PTR [r11 + 0x8]
    jne abisan_fail
    cmp rsp, QWORD PTR [r11 + 0x10]
    jne abisan_fail

    # Put the original return address back in place
    mov r11, QWORD PTR [r11 + 0x18]
    mov [rsp], r11
    ret

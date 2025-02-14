.intel_syntax noprefix

.globl abisan_f_entry_instrumentation
abisan_f_entry_instrumentation:
    mov QWORD PTR [0xdadf000], rbx
    push rbx
    mov rbx, QWORD PTR [rsp + 16] # Grab f's return address
    mov QWORD PTR [0xdadf008], rbx
    pop rbx
    mov QWORD PTR [rsp + 8], offset abisan_f_exit_instrumentation
    xor rbx, rbx
    add rbx, rdi
    ret
abisan_f_exit_instrumentation:
    cmp rbx, QWORD PTR [0xdadf000]
    jne abisan_f_exit_instrumentation_fail
    mov rdi, QWORD PTR [0xdadf008]
    mov QWORD PTR [rsp], rdi
    ret
abisan_f_exit_instrumentation_fail:
    mov rdi, 1
    call exit


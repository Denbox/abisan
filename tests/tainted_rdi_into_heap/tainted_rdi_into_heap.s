.intel_syntax noprefix

.globl tainted_rdi_into_heap
tainted_rdi_into_heap:
    mov rdi, 8
    call malloc
    mov qword ptr [rax], rdi
    ret

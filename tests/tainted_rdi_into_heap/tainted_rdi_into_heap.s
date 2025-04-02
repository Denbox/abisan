.intel_syntax noprefix

.globl f
f:
    ret

.globl tainted_rdi_into_heap
tainted_rdi_into_heap:
    # TODO: remove f from this test. malloc should be enough to taint rdi.
    mov rdi, 8
    call malloc
    push rax
    call f
    pop rax
    mov qword ptr [rax], rdi
    ret

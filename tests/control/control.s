.intel_syntax noprefix

.globl control
control:

	  # Mov into stack
	  mov QWORD PTR[rsp - 0x40], r11
	
    # Add up the first 7 arguments into rax
    xor rax, rax
    add rax, rdi
    add rax, rsi
    add rax, rdx
    add rax, rcx
    add rax, r8
    add rax, r9
    add rax, QWORD PTR [rsp + 0x08]

    # mov into the heap
    push rax
    mov rdi, 1
    call malloc
    mov byte ptr [rax], 0
    mov rdi, rax
    call free
    pop rax

    # cmov from the heap
    push rax
    mov rdi, 4
    call malloc
    mov dword ptr [rax], 0xdeadbeef
    mov rdi, 1
    cmp rdi, 0
    cmova edi, dword ptr [rax]
    mov rdi, rax
    call free
    pop rax

    # Zero all volatile registers
    xor rdi, rdi
    xor rsi, rsi
    xor rdx, rdx
    xor rcx, rcx
    xor r8, r8
    xor r9, r9
    xor r10, r10
    xor r11, r11
    xor r11, r11

    # Zero the red zone
    mov QWORD PTR [rsp - 0x08], rcx
    mov QWORD PTR [rsp - 0x10], rcx
    mov QWORD PTR [rsp - 0x18], rcx
    mov QWORD PTR [rsp - 0x20], rcx
    mov QWORD PTR [rsp - 0x28], rcx
    mov QWORD PTR [rsp - 0x30], rcx
    mov QWORD PTR [rsp - 0x38], rcx
    mov QWORD PTR [rsp - 0x40], rcx
    mov QWORD PTR [rsp - 0x48], rcx
    mov QWORD PTR [rsp - 0x50], rcx
    mov QWORD PTR [rsp - 0x58], rcx
    mov QWORD PTR [rsp - 0x60], rcx
    mov QWORD PTR [rsp - 0x68], rcx
    mov QWORD PTR [rsp - 0x70], rcx
    mov QWORD PTR [rsp - 0x78], rcx
    mov QWORD PTR [rsp - 0x80], rcx

    # Conditional mov from below the red zone with a false condition
    mov rdi, 1
    cmp rdi, 0
    cmovbe rcx, QWORD PTR [rsp - 0x88]

    # Conditional mov in the red zone with a true condition
    cmova rcx, QWORD PTR [rsp - 0x80]

    # Mov from above the frame
  	mov rcx, QWORD PTR [rsp + 0x8]

	  ret

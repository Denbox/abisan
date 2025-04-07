.intel_syntax noprefix 

.globl control
control:

	# Mov into stack
	mov QWORD PTR[rsp+0x10], r11
	
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

    # Mov from above the frame
  	mov rcx, QWORD PTR [rsp + 0x8]

	ret

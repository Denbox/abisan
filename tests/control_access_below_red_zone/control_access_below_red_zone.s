.intel_syntax noprefix

.globl control_access_below_red_zone
control_access_below_red_zone:
	# This assumes that the redzone is enabled. If it is disabled, abisan will throw an error
    # Zero rax
    xor rax, rax
   

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

	ret

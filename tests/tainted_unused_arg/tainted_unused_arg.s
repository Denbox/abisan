.intel_syntax noprefix

	# Current Behavior:
	# r9 is set untainted at first call to f, so we do not throw an error

    # Expected Behavior:
    # r9 has not been written to before it is read, so we should throw an error
.globl f
f:
	mov rax, rdi
	add rax, rsi
	add rax, r9  # argument register not in this function
	ret

.globl tainted_unused_arg
tainted_unused_arg:
	mov rdi, 0x10
	mov rsi, 0x20
	call f
	ret

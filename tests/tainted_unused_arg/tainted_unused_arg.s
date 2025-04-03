.intel_syntax noprefix

	# Current Behavior:
	# r9 is untainted at first call to f, so we do not throw an error
	# abisan marks all arg regs as tainted after leaving f
	# call f for second time
	# r9 is now marked as tainted, so abisan throws error

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
	mov rdi, 0x30
	mov rsi, 0x40
	call f
	ret

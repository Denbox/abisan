# ABI Sanitizer

#### Known Bugs:
- Reads from extraneous argument registers are not detected in the first function call of a program due to initialization of argument register taint states to untainted in [abisan_runtime.c](https://github.com/Denbox/abisan/blob/93148cb0cf7e67b8e48f2a88489d3fad76242a7d/abisan_runtime.c)

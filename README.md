# ABI Sanitizer

#### Known Bugs:
- Reads from extraneous argument registers are not detected in the first function call of a program due to initialization of argument register taint states to untainted in [abisan_runtime.c](https://github.com/Denbox/abisan/blob/93148cb0cf7e67b8e48f2a88489d3fad76242a7d/abisan_runtime.c)
  - See outdated [tainted_unused_arg.s](https://github.com/Denbox/abisan/blob/5d7793d24e5e2dea19aaa4215b49401b1504a570/tests/tainted_unused_arg/tainted_unused_arg.s) 

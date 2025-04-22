# ABI Sanitizer

### Environment Variables:
ABI San utilizes environment variables to allow users to tune values which impact how the program adheres to the ABI standards.
Environment Variables should be entered as separate variables, each beginning with the prefix `ABISAN_TUNABLES`

We currently support the following environment variable tunables:
1. `ABISAN_TUNABLES_REDZONE_ENABLED` a `1` or `0` indicating whether the Red Zone below the stack exists. If enabled, `REDZONE_SIZE` will be `0x80`
2. `ABISAN_TUNABLES_STACK_SIZE` an integer greater or equal to the size of the Red Zone (non-negative if the Red Zone is disabled). Default value is  `0x800000` or 8Mb
3. `ABISAN_TUNABLES_SYNTAX` a string either "intel" or "att" indicating the syntax of assembly you wish to instrument. Default value is `intel`


### Known Bugs:
- Reads from extraneous argument registers are not detected in the first function call of a program due to initialization of argument register taint states to untainted in [abisan_runtime.c](https://github.com/Denbox/abisan/blob/93148cb0cf7e67b8e48f2a88489d3fad76242a7d/abisan_runtime.c)
  - See outdated [tainted_unused_arg.s](https://github.com/Denbox/abisan/blob/5d7793d24e5e2dea19aaa4215b49401b1504a570/tests/tainted_unused_arg/tainted_unused_arg.s) 

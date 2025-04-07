# ABI Sanitizer

### Environment Variables:
ABI San utilizes environment variables to allow users to tune values which impact how the program adheres to the ABI standards.
Environment Variables should be entered as a `;` separated list under the variable name `ABISAN_TUNABLES`

The order of the list must follow the order of tunables listed below.

We currently support the following environment variable tunables:
1. `REDZONE_ENABLED` a boolean holding `1` or `0` indicating whether the Red Zone below the stack exists. If enabled, `REDZONE_SIZE` will be `0x80`
2. `STACK_SIZE` a hexadecimal integer greater or equal to the size of the Red Zone (non-negative if the Red Zone is disabled) and aligned to 8 bytes. Values should be written in hexidecimal as below. Default value is  `0x800000` or 8Mb

ex. `ABISAN_TUNABLES="REDZONE_ENABLED=1;STACK_SIZE=0x8000000"`


### Known Bugs:
- Reads from extraneous argument registers are not detected in the first function call of a program due to initialization of argument register taint states to untainted in [abisan_runtime.c](https://github.com/Denbox/abisan/blob/93148cb0cf7e67b8e48f2a88489d3fad76242a7d/abisan_runtime.c)
  - See outdated [tainted_unused_arg.s](https://github.com/Denbox/abisan/blob/5d7793d24e5e2dea19aaa4215b49401b1504a570/tests/tainted_unused_arg/tainted_unused_arg.s) 

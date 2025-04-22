.intel_syntax noprefix

.globl access_below_red_zone
access_below_red_zone:
    mov al, BYTE PTR [rsp - 0x81]
    ret

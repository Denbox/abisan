.intel_syntax noprefix

.globl access_within_red_zone
access_within_red_zone:
    mov al, BYTE PTR [rsp - 0x80]
    ret

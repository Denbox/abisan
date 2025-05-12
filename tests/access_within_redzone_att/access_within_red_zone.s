.globl access_within_red_zone
access_within_red_zone:
    movb -0x80(%rsp), %al
    ret

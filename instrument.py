import os
import random
import re
import sys


def remove_comment(line: bytes) -> bytes:
    split_line: list[bytes] = line.split(b"#", maxsplit=1)
    if len(split_line) > 0:
        if split_line[0].endswith(b"'") and split_line[1].startswith(b"'"):
            return split_line[0] + b"#" + remove_comment(split_line[1])
        return split_line[0]
    return line


def get_memory_operand(line: bytes) -> bytes | None:
    tokens: list[bytes] = line.split(maxsplit=1)
    if len(tokens) != 2:
        return None

    mnemonic: bytes = tokens[0].lower()
    if mnemonic == b"lea":
        return None

    for operand in (token.strip() for token in tokens[1].split(b",")):
        if b"[" in operand:
            return operand
    return None


def get_memory_cmov_address_and_condition(line: bytes) -> tuple[bytes, bytes] | None:
    tokens: list[bytes] = line.split(maxsplit=1)
    if len(tokens) != 2:
        return None

    mnemonic: bytes = tokens[0].lower()
    if not mnemonic.startswith(b"cmov"):
        return None

    operands: list[bytes] = [token.strip() for token in tokens[1].split(b",")]
    assert len(operands) == 2
    memory_operand: bytes = operands[0] if b"[" in operands[0] else operands[1]
    if b"[" not in memory_operand:
        # This is a register-register mov
        return None
    return memory_operand, mnemonic[len("cmov"):]


def get_label_name(line: bytes) -> bytes | None:
    tokens: list[bytes] = line.split(b":", maxsplit=1)
    if len(tokens) > 0:
        return tokens[0]
    return None


def get_global_name(line: bytes) -> bytes | None:
    tokens: list[bytes] = line.split(maxsplit=2)
    if (
        len(tokens) >= 2
        and tokens[0].lower() in (b".globl", b".global")
        and tokens[1] != b"_start"
    ):
        return tokens[1]
    return None


STACK_SIZE_THRESHOLD: int = 0x21000

def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <assembly_file>", file=sys.stderr)
        sys.exit(1)

    _, infile_suffix = sys.argv[1].rsplit(".", maxsplit=1)
    outfile: str = sys.argv[1] + ".abisan." + infile_suffix
    fd: int = os.open(outfile, os.O_CREAT | os.O_WRONLY, mode=0o644)

    with open(sys.argv[1], "rb") as f:
        source_code: bytes = f.read()

    lines: list[bytes] = source_code.splitlines(keepends=True)
    global_symbols: list[bytes] = [
        symbol for symbol in map(get_global_name, lines) if symbol is not None
    ]

    for i, line in enumerate(map(bytes.rstrip, map(remove_comment, lines))):
        cmov_addr_and_condition: tuple[bytes, bytes] | None = get_memory_cmov_address_and_condition(line)
        memory_operand: bytes | None = get_memory_operand(line)
        if cmov_addr_and_condition is not None:
            cmov_address, cmov_condition = cmov_addr_and_condition
            os.write(fd, b"    pushfq\n")
            os.write(fd, b"    push rax\n")
            os.write(fd, b"    push rdx\n")
            os.write(fd, b"    lea rdx, " + cmov_address + b"\n")
            os.write(fd, b"    mov rax, rsp\n")
            os.write(fd, b"    cmov" + cmov_condition + b" rax, rdx\n")
            os.write(fd, b"    neg rax\n")
            os.write(fd, b"    dec rax\n")
            os.write(fd, b"    sub rax, 0x80\n")
            os.write(fd, b"    add rax, rsp\n")
            os.write(fd, f"    cmp rax, {STACK_SIZE_THRESHOLD}\n".encode("ascii"))
            os.write(fd, b"    jb abisan_fail_mov_below_rsp\n")
            os.write(fd, b"    pop rdx\n")
            os.write(fd, b"    pop rax\n")
            os.write(fd, b"    popfq\n")
        elif memory_operand is not None:
            os.write(fd, b"    pushfq\n")
            os.write(fd, b"    push rax\n")
            os.write(fd, b"    lea rax, " + memory_operand + b"\n")
            os.write(fd, b"    neg rax\n")
            os.write(fd, b"    dec rax\n")
            os.write(fd, b"    sub rax, 0x80\n")
            os.write(fd, b"    add rax, rsp\n")
            os.write(fd, f"    cmp rax, {STACK_SIZE_THRESHOLD}\n".encode("ascii"))
            os.write(fd, b"    jb abisan_fail_mov_below_rsp\n")
            os.write(fd, b"    pop rax\n")
            os.write(fd, b"    popfq\n")

        os.write(fd, line + b"\n")

        if get_label_name(line) in global_symbols:
            os.write(fd, b"    call abisan_function_entry\n")


if __name__ == "__main__":
    main()

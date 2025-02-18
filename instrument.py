import sys
import re


def get_memory_move_address(line: bytes) -> bytes | None:
    tokens: list[bytes] = line.split(maxsplit=1)
    if len(tokens) != 2:
        return None

    mnemonic: bytes = tokens[0]
    if mnemonic != b"mov":
        return None

    operands: list[bytes] = [token.strip() for token in tokens[1].split(b",")]
    assert len(operands) == 2
    memory_operand: bytes = operands[0] if b"[" in operands[0] else operands[1]
    if b"[" not in memory_operand:
        # This is a register-register mov
        return None
    return memory_operand


def get_label_name(line: bytes) -> bytes | None:
    tokens: list[bytes] = line.split()
    if len(tokens) >= 1 and tokens[0].endswith(b":"):
        return tokens[0][:-1]
    return None


def get_global_name(line: bytes) -> bytes | None:
    tokens: list[bytes] = line.split()
    if (
        len(tokens) >= 2
        and tokens[0].lower() in (b".globl", b".global")
        and tokens[1] != b"_start"
    ):
        return tokens[1]
    return None


CALL_ABISAN: bytes = b"call abisan_function_entry\n"
PUSH_FLAGS: bytes = b"pushfq\n"
POP_FLAGS: bytes = b"popfq\n"
PUSH_RAX: bytes = b"push rax\n"
POP_RAX: bytes = b"pop rax\n"

def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <assembly_file>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        source_code: bytes = f.read()

    lines: list[bytes] = source_code.splitlines(keepends=True)
    global_symbols: list[bytes] = [
        symbol for symbol in map(get_global_name, lines) if symbol is not None
    ]

    for i, line in enumerate(lines):
        move_address: bytes = get_memory_move_address(line)
        if move_address is not None:
            sys.stdout.buffer.write(PUSH_FLAGS)
            sys.stdout.buffer.write(PUSH_RAX)
            sys.stdout.buffer.write(b"lea rax, " + move_address + b"\n")
            sys.stdout.buffer.write(b"cmp rax, rsp\n")
            sys.stdout.buffer.write(b"jb abisan_fail_mov_below_rsp\n")
            sys.stdout.buffer.write(POP_RAX)
            sys.stdout.buffer.write(POP_FLAGS)

        sys.stdout.buffer.write(line)
        if get_label_name(line) in global_symbols and (
            i == len(lines) - 1 or not lines[i + 1].endswith(CALL_ABISAN)
        ):
            sys.stdout.buffer.write(CALL_ABISAN)


if __name__ == "__main__":
    main()

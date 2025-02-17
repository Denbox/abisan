import sys
import re


def get_label(line: bytes) -> bytes | None:
    tokens: list[bytes] = line.split()
    if len(tokens) >= 1 and tokens[0].endswith(b":"):
        return tokens[0][:-1]
    return None


def get_global(line: bytes) -> bytes | None:
    tokens: list[bytes] = line.split()
    if len(tokens) >= 2 and tokens[0].lower() in (b".globl", b".global") and tokens[1] != b"_start":
        return tokens[1]
    return None


CALL_ABISAN: bytes = b"call abisan_function_entry\n"

def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <assembly_file>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        source_code: bytes = f.read()

    lines: list[bytes] = source_code.splitlines(keepends=True)
    global_symbols: list[bytes] = [symbol for symbol in map(get_global, lines) if symbol is not None]

    for i, line in enumerate(lines):
        if i != len(lines) - 1 and lines[i + 1].endswith(CALL_ABISAN): # If this function is already instrumented, keep going
            continue
        sys.stdout.buffer.write(line)
        if get_label(line) in global_symbols:
            sys.stdout.buffer.write(CALL_ABISAN)


if __name__ == "__main__":
    main()

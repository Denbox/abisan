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


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <assembly_file>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        source_code: bytes = f.read()

    lines: list[bytes] = source_code.splitlines(keepends=True)
    global_symbols: list[bytes] = [symbol for symbol in map(get_global, lines) if symbol is not None]

    for i, line in enumerate(lines):
        next_line: bytes = b"    "  # The next nonempty, non-label line (used to infer indentation)
        for j in range(i, len(lines)):
            if not lines[j].isspace() and get_label(lines[j]) is None:
                next_line = lines[j]
        sys.stdout.buffer.write(line)
        if get_label(line) in global_symbols:
            whitespace_prefix_match: re.Match[bytes] | None = re.match(
                rb"^(?P<whitespace_prefix>\s*)", next_line
            )
            assert whitespace_prefix_match is not None
            whitespace_prefix: bytes = whitespace_prefix_match["whitespace_prefix"]
            sys.stdout.buffer.write(whitespace_prefix + b"call abisan_function_entry\n")


if __name__ == "__main__":
    main()

import sys
import re
import itertools

def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <assembly_file>", file=sys.stderr)
        sys.exit(1)

    with open(sys.argv[1], "rb") as f:
        source_code: bytes = f.read()
    
    lines: list[bytes] = source_code.splitlines(keepends=True)

    symbols: list[bytes] = [line.split()[1] for line in lines if len(line.split()) == 2 and line.split()[0] in (b".globl", b".global")]

    for line, next_line in itertools.zip_longest(lines, lines[1:]):
        if next_line is None:
            next_line = b"    "
        sys.stdout.buffer.write(line)
        tokens: list[bytes] = line.split()
        if len(tokens) >= 1 and tokens[0].endswith(b":") and tokens[0][:-1] in symbols:
            whitespace_prefix_match: re.Match[bytes] | None = re.match(rb"^(?P<whitespace_prefix>\s*)", next_line)
            assert whitespace_prefix_match is not None
            whitespace_prefix: bytes = whitespace_prefix_match["whitespace_prefix"]
            sys.stdout.buffer.write(whitespace_prefix + b"call abisan_function_entry # Added by preprocess.py\n")

if __name__ == "__main__":
    main()

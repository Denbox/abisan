import os
import subprocess
import sys

import capstone  # type: ignore
from capstone import Cs, CsInsn
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection

cs: Cs = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True


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


def get_global_name(line: bytes) -> bytes | None:
    tokens: list[bytes] = line.split(maxsplit=2)
    if (
        len(tokens) >= 2
        and tokens[0].lower() in (b".globl", b".global")
        and tokens[1] != b"_start"
    ):
        return tokens[1]
    return None


def remove_comment(line: bytes) -> bytes:
    split_line: list[bytes] = line.split(b"#", maxsplit=1)
    if len(split_line) > 0:
        if split_line[0].endswith(b"'") and split_line[1].startswith(b"'"):
            return split_line[0] + b"#" + remove_comment(split_line[1])
        return split_line[0]
    return line


def get_label_name(line: bytes) -> bytes | None:
    tokens: list[bytes] = line.split(b":", maxsplit=1)
    if len(tokens) > 1:
        return tokens[0]
    return None


def is_label(line: bytes) -> bool:
    return get_label_name(line) is not None


def is_instruction(line: bytes) -> bool:
    line = line.lstrip()
    return len(line) > 0 and not line.startswith(b".") and not is_label(line)


def get_intermediate_labels(elf_file: ELFFile) -> dict[bytes, CsInsn]:
    result: list[tuple[str, int]] = []
    for i in range(elf_file.num_sections()):
        section: Section = elf_file.get_section(i)
        if isinstance(section, SymbolTableSection):
            result += [
                (symbol.name, symbol.entry["st_value"])
                for symbol in section.iter_symbols()
                if ".abisan.intermediate." in symbol.name
            ]
    the_code: bytes = elf_file.get_section_by_name(".text").data()
    return {
        name.encode("latin1"): list(cs.disasm(the_code[offset:], offset=0, count=1))[0]
        for name, offset in result
    }


STACK_SIZE_THRESHOLD: int = 0x21000


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <assembly_file>", file=sys.stderr)
        sys.exit(1)

    input_file_name: str = sys.argv[1]
    _, input_file_name_suffix = input_file_name.rsplit(".", maxsplit=1)
    intermediate_file_name: str = (
        input_file_name + ".abisan.intermediate." + input_file_name_suffix
    )
    intermediate_fd: int = os.open(
        intermediate_file_name, os.O_CREAT | os.O_WRONLY, mode=0o644
    )
    intermediate_object_file_name: str = intermediate_file_name + ".o"

    with open(sys.argv[1], "rb") as f:
        source_code: bytes = f.read()

    lines: list[bytes] = source_code.splitlines(keepends=True)

    global_symbols: list[bytes] = [
        symbol for symbol in map(get_global_name, lines) if symbol is not None
    ]

    # Add a global label before every instruction
    instruction_line_numbers: dict[bytes, int] = {}
    for i, line in enumerate(map(bytes.rstrip, map(remove_comment, lines))):
        if is_instruction(line):
            label_name: bytes = f"{intermediate_file_name}_{i}".encode("ascii")
            os.write(intermediate_fd, label_name + b":\n")
            instruction_line_numbers[label_name] = i
        os.write(intermediate_fd, line + b"\n")

    # Assemble the result
    subprocess.run(
        ["as", intermediate_file_name, "-o", intermediate_object_file_name], check=True
    )

    intermediate_labels: dict[bytes, CsInsn] = get_intermediate_labels(
        ELFFile.load_from_path(intermediate_object_file_name)
    )

    # Maps line numbers to CsInsns
    assembled_instructions: dict[int, CsInsn] = {
        i: intermediate_labels[label] for label, i in instruction_line_numbers.items()
    }

    output_file_name: str = input_file_name + ".abisan." + input_file_name_suffix
    output_fd: int = os.open(output_file_name, os.O_CREAT | os.O_WRONLY, mode=0o644)

    for i, line in enumerate(map(bytes.rstrip, map(remove_comment, lines))):
        if i in assembled_instructions:
            insn: CsInsn = assembled_instructions[i]
            if insn.op_count(capstone.CS_OP_MEM) > 0 and insn.mnemonic != "lea":
                memory_operand: bytes | None = get_memory_operand(line)
                assert memory_operand is not None
                if insn.mnemonic.startswith("cmov"):
                    os.write(output_fd, b"    pushfq\n")
                    os.write(output_fd, b"    push rax\n")
                    os.write(output_fd, b"    push rdx\n")
                    os.write(output_fd, b"    lea rdx, " + memory_operand + b"\n")
                    os.write(output_fd, b"    mov rax, rsp\n")
                    os.write(
                        output_fd, b"    " + insn.mnemonic.encode("ascii") + b" rax, rdx\n"
                    )
                    os.write(output_fd, b"    neg rax\n")
                    os.write(output_fd, b"    dec rax\n")
                    os.write(output_fd, b"    sub rax, 0x80\n")
                    os.write(output_fd, b"    add rax, rsp\n")
                    os.write(
                        output_fd, f"    cmp rax, {STACK_SIZE_THRESHOLD}\n".encode("ascii")
                    )
                    os.write(output_fd, b"    jb abisan_fail_mov_below_rsp\n")
                    os.write(output_fd, b"    pop rdx\n")
                    os.write(output_fd, b"    pop rax\n")
                    os.write(output_fd, b"    popfq\n")
                else:
                    os.write(output_fd, b"    pushfq\n")
                    os.write(output_fd, b"    push rax\n")
                    os.write(output_fd, b"    lea rax, " + memory_operand + b"\n")
                    os.write(output_fd, b"    neg rax\n")
                    os.write(output_fd, b"    dec rax\n")
                    os.write(output_fd, b"    sub rax, 0x80\n")
                    os.write(output_fd, b"    add rax, rsp\n")
                    os.write(
                        output_fd, f"    cmp rax, {STACK_SIZE_THRESHOLD}\n".encode("ascii")
                    )
                    os.write(output_fd, b"    jb abisan_fail_mov_below_rsp\n")
                    os.write(output_fd, b"    pop rax\n")
                    os.write(output_fd, b"    popfq\n")
        os.write(output_fd, line + b"\n")

        if get_label_name(line) in global_symbols:
            os.write(output_fd, b"    call abisan_function_entry\n")


if __name__ == "__main__":
    main()

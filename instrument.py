import os
import subprocess
import sys

import capstone  # type: ignore
from capstone import Cs, CsInsn, x86_const
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


def needs_taint_check_for_read(insn: CsInsn) -> bool:
    if insn.mnemonic == "push":
        return False

    reg_ops: set[int] = get_registers_read(insn)
    if (
        insn.mnemonic in ("xor", "sub")
        and len(reg_ops) == 1
        and insn.op_count(capstone.CS_OP_REG) == 2
    ):
        return False
    return True


_UNUSED_REGISTERS: set[int] = {x86_const.X86_REG_RIP, x86_const.X86_REG_RSP}


def get_registers_read(insn: CsInsn) -> set[int]:
    result: set[int] = set()
    result.update(insn.regs_read)
    for op in insn.operands:
        if op.type == capstone.CS_OP_REG and op.access & capstone.CS_AC_READ:
            result.add(op.reg)
        elif op.type == capstone.CS_OP_MEM:
            if op.mem.base != 0:
                result.add(op.mem.base)
            if op.mem.index != 0:
                result.add(op.mem.index)
            if op.mem.segment != 0:
                result.add(op.mem.segment)
    return set(
        filter(lambda r: r not in _UNUSED_REGISTERS, map(register_normalize, result))
    )


def get_registers_written(insn: CsInsn) -> set[int]:
    result: set[int] = set()
    result.update(insn.regs_write)
    for op in insn.operands:
        if op.type == capstone.CS_OP_REG and op.access & capstone.CS_AC_WRITE:
            result.add(op.reg)
    return set(
        filter(lambda r: r not in _UNUSED_REGISTERS, map(register_normalize, result))
    )


def register_normalize(r: int) -> int:
    match r:
        case (
            x86_const.X86_REG_AH
            | x86_const.X86_REG_AL
            | x86_const.X86_REG_AX
            | x86_const.X86_REG_EAX
            | x86_const.X86_REG_RAX
        ):
            return x86_const.X86_REG_RAX
        case (
            x86_const.X86_REG_BH
            | x86_const.X86_REG_BL
            | x86_const.X86_REG_BX
            | x86_const.X86_REG_EBX
            | x86_const.X86_REG_RBX
        ):
            return x86_const.X86_REG_RBX
        case (
            x86_const.X86_REG_CH
            | x86_const.X86_REG_CL
            | x86_const.X86_REG_CX
            | x86_const.X86_REG_ECX
            | x86_const.X86_REG_RCX
        ):
            return x86_const.X86_REG_RCX
        case (
            x86_const.X86_REG_DH
            | x86_const.X86_REG_DL
            | x86_const.X86_REG_DX
            | x86_const.X86_REG_EDX
            | x86_const.X86_REG_RDX
        ):
            return x86_const.X86_REG_RDX

        case (
            x86_const.X86_REG_DIL
            | x86_const.X86_REG_DI
            | x86_const.X86_REG_EDI
            | x86_const.X86_REG_RDI
        ):
            return x86_const.X86_REG_RDI
        case (
            x86_const.X86_REG_SIL
            | x86_const.X86_REG_SI
            | x86_const.X86_REG_ESI
            | x86_const.X86_REG_RSI
        ):
            return x86_const.X86_REG_RSI

        case (
            x86_const.X86_REG_R8B
            | x86_const.X86_REG_R8W
            | x86_const.X86_REG_R8D
            | x86_const.X86_REG_R8
        ):
            return x86_const.X86_REG_R8
        case (
            x86_const.X86_REG_R9B
            | x86_const.X86_REG_R9W
            | x86_const.X86_REG_R9D
            | x86_const.X86_REG_R9
        ):
            return x86_const.X86_REG_R9
        case (
            x86_const.X86_REG_R10B
            | x86_const.X86_REG_R10W
            | x86_const.X86_REG_R10D
            | x86_const.X86_REG_R10
        ):
            return x86_const.X86_REG_R10
        case (
            x86_const.X86_REG_R11B
            | x86_const.X86_REG_R11W
            | x86_const.X86_REG_R11D
            | x86_const.X86_REG_R11
        ):
            return x86_const.X86_REG_R11
        case (
            x86_const.X86_REG_R12B
            | x86_const.X86_REG_R12W
            | x86_const.X86_REG_R12D
            | x86_const.X86_REG_R12
        ):
            return x86_const.X86_REG_R12
        case (
            x86_const.X86_REG_R13B
            | x86_const.X86_REG_R13W
            | x86_const.X86_REG_R13D
            | x86_const.X86_REG_R13
        ):
            return x86_const.X86_REG_R13
        case (
            x86_const.X86_REG_R14B
            | x86_const.X86_REG_R14W
            | x86_const.X86_REG_R14D
            | x86_const.X86_REG_R14
        ):
            return x86_const.X86_REG_R14
        case (
            x86_const.X86_REG_R15B
            | x86_const.X86_REG_R15W
            | x86_const.X86_REG_R15D
            | x86_const.X86_REG_R15
        ):
            return x86_const.X86_REG_R15

        case (
            x86_const.X86_REG_BPL
            | x86_const.X86_REG_BP
            | x86_const.X86_REG_EBP
            | x86_const.X86_REG_RBP
        ):
            return x86_const.X86_REG_RBP
        case (
            x86_const.X86_REG_SPL
            | x86_const.X86_REG_SP
            | x86_const.X86_REG_ESP
            | x86_const.X86_REG_RSP
        ):
            return x86_const.X86_REG_RSP

        case x86_const.X86_REG_IP | x86_const.X86_REG_EIP | x86_const.X86_REG_RIP:
            return x86_const.X86_REG_RIP

        case x86_const.X86_REG_EFLAGS:
            return x86_const.X86_REG_EFLAGS

    print("Unsupported register {cs.reg_name(r)}", file=sys.stderr)
    sys.exit(1)


def cs_to_taint_idx(r: int) -> int:
    match r:
        case x86_const.X86_REG_RAX:
            return 0
        case x86_const.X86_REG_RBX:
            return 1
        case x86_const.X86_REG_RDX:
            return 2
        case x86_const.X86_REG_RCX:
            return 3
        case x86_const.X86_REG_RDI:
            return 4
        case x86_const.X86_REG_RSI:
            return 5
        case x86_const.X86_REG_R8:
            return 6
        case x86_const.X86_REG_R9:
            return 7
        case x86_const.X86_REG_R10:
            return 8
        case x86_const.X86_REG_R11:
            return 9
        case x86_const.X86_REG_R12:
            return 10
        case x86_const.X86_REG_R13:
            return 11
        case x86_const.X86_REG_R14:
            return 12
        case x86_const.X86_REG_R15:
            return 13
        case x86_const.X86_REG_RBP:
            return 14
        case x86_const.X86_REG_EFLAGS:
            return 15

    print("Unsupported register {cs.reg_name(r)}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <assembly_file>", file=sys.stderr)
        sys.exit(1)

    input_file_name: str = sys.argv[1]
    _, input_file_name_suffix = input_file_name.rsplit(".", maxsplit=1)
    intermediate_file_name: str = (
        input_file_name + ".abisan.intermediate." + input_file_name_suffix
    )
    intermediate_object_file_name: str = intermediate_file_name + ".o"

    with open(sys.argv[1], "rb") as f:
        source_code: bytes = f.read()

    lines: list[bytes] = source_code.splitlines(keepends=True)

    # Add a global label before every instruction
    with open(intermediate_file_name, "xb") as f:
        instruction_line_numbers: dict[bytes, int] = {}
        for i, line in enumerate(map(bytes.rstrip, map(remove_comment, lines))):
            if is_instruction(line):
                label_name: bytes = (
                    f"{intermediate_file_name.replace('/', '_slash_')}_{i}".encode("ascii")
                )
                f.write(label_name + b":\n")
                instruction_line_numbers[label_name] = i
            f.write(line + b"\n")

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

    global_symbols: list[bytes] = [
        symbol for symbol in map(get_global_name, lines) if symbol is not None
    ]

    with open(output_file_name, "xb") as f:
        for i, line in enumerate(map(bytes.rstrip, map(remove_comment, lines))):
            insn: CsInsn = assembled_instructions.get(i)
            if insn is not None:
                registers_read: set[int] = get_registers_read(insn)
                registers_written: set[int] = get_registers_written(insn)
                if insn.op_count(capstone.CS_OP_MEM) > 0 and insn.mnemonic != "lea":
                    memory_operand: bytes | None = get_memory_operand(line)
                    assert memory_operand is not None
                    if insn.mnemonic.startswith("cmov"):
                        f.write(b"    pushfq\n")
                        f.write(b"    push rax\n")
                        f.write(b"    push rdx\n")
                        f.write(b"    lea rdx, " + memory_operand + b"\n")
                        f.write(b"    mov rax, rsp\n")
                        f.write(
                            b"    " + insn.mnemonic.encode("ascii") + b" rax, rdx\n"
                        )
                        f.write(b"    add rax, 0x80\n")
                        f.write(b"    cmp rax, rsp\n")
                        f.write(b"    jb abisan_fail_mov_below_rsp\n")
                        f.write(b"    pop rdx\n")
                        f.write(b"    pop rax\n")
                        f.write(b"    popfq\n")
                    else:
                        f.write(b"    pushfq\n")
                        f.write(b"    push rax\n")
                        f.write(b"    lea rax, " + memory_operand + b"\n")
                        f.write(b"    add rax, 0x80\n")
                        f.write(b"    cmp rax, rsp\n")
                        f.write(b"    jb abisan_fail_mov_below_rsp\n")
                        f.write(b"    pop rax\n")
                        f.write(b"    popfq\n")

                if needs_taint_check_for_read(insn):
                    for r in get_registers_read(insn):
                        f.write(b"    pushfq\n")
                        f.write(b"    push rax\n")
                        f.write(
                            f"    lea rax, offset abisan_taint_state[rip + {cs_to_taint_idx(r)}]\n".encode(
                                "ascii"
                            ),
                        )
                        f.write(b"    mov al, byte ptr [rax]\n")
                        f.write(b"    cmp al, 0\n")
                        f.write(
                            f"    jne abisan_fail_taint_{cs.reg_name(r)}\n".encode()
                        )
                        f.write(b"    pop rax\n")
                        f.write(b"    popfq\n")

                for r in get_registers_written(insn):
                    f.write(b"    push rax\n")
                    f.write(
                        f"    lea rax, offset abisan_taint_state[rip + {cs_to_taint_idx(r)}]\n".encode(
                            "ascii"
                        ),
                    )
                    f.write(b"    mov byte ptr [rax], 0\n")
                    f.write(b"    pop rax\n")

            f.write(line + b"\n")

            if get_label_name(line) in global_symbols:
                f.write(b"    call abisan_function_entry\n")


if __name__ == "__main__":
    main()

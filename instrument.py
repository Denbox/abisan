import os
import subprocess
import sys

import capstone  # type: ignore
from capstone import Cs, CsInsn, x86_const
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection

cs: Cs = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True

TAINT_STATE_RAX: int = 0
# TAINT_STATE_RBX: int = 1
TAINT_STATE_RCX: int = 2
TAINT_STATE_RDX: int = 3
TAINT_STATE_RDI: int = 4
TAINT_STATE_RSI: int = 5
TAINT_STATE_R8: int = 6
TAINT_STATE_R9: int = 7
TAINT_STATE_R10: int = 8
TAINT_STATE_R11: int = 9
# TAINT_STATE_R12: int = 10
# TAINT_STATE_R13: int = 11
# TAINT_STATE_R14: int = 12
# TAINT_STATE_R15: int = 13
# TAINT_STATE_RBP: int = 14
# TAINT_STATE_EFLAGS: int = 15

INIT_RED_ZONE_SIZE: int = 0x80
INIT_STACK_SIZE: int = 0x800000


def get_memory_operand(line: bytes) -> bytes:
    tokens: list[bytes] = line.split(maxsplit=1)
    assert len(tokens) == 2

    mnemonic: bytes = tokens[0].lower()
    assert mnemonic != b"lea"

    # TODO: Support AT&T syntax
    # TODO: Support single-quoted [ and ,.
    for operand in (token.strip() for token in tokens[1].split(b",")):
        if b"[" in operand:
            return operand
    assert False


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
                if symbol.name.startswith("abisan_intermediate")
            ]
    the_code: bytes = elf_file.get_section_by_name(".text").data()
    return {
        name.encode("latin1"): list(cs.disasm(the_code[offset:], offset=0, count=1))[0]
        for name, offset in result
    }


def needs_taint_check_for_read(insn: CsInsn) -> bool:
    # generate_reg_taint_check handles mov into stack
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


def generate_cmov_instrumentation(
    line: bytes, insn: CsInsn, red_zone_size: int, stack_size: int
) -> bytes:
    return (
        b"\n".join(
            (
                b"    pushfq",
                b"    push rax",
                b"    push rbx",
                b"    lea rbx, " + get_memory_operand(line),
                b"    mov rax, rsp",
                b"    " + insn.mnemonic.encode("ascii") + b" rax, rbx",
                b"    add rax, " + hex(red_zone_size).encode("ascii"),
                b"    cmp rax, rsp",
                b"    setb bl",
                b"    add rax, " + hex(stack_size - red_zone_size).encode("ascii"),
                b"    cmp rax, rsp",
                b"    seta bh",
                b"    add bl, bh",
                b"    cmp bl, 2",
                b"    je abisan_fail_mov_below_rsp",
                b"    pop rbx",
                b"    pop rax",
                b"    popfq",
            )
        )
        + b"\n"
    )


def generate_generic_memory_instrumentation(
    line: bytes, red_zone_size: int, stack_size: int
) -> bytes:
    # TODO: Make size of red zone a tunable
    # TODO: Make size of stack a tunable
    return (
        b"\n".join(
            (
                b"    pushfq",
                b"    push rax",
                b"    push rbx",
                b"    lea rax, " + get_memory_operand(line),
                b"    add rax, " + hex(red_zone_size).encode("ascii"),
                b"    cmp rax, rsp",
                b"    setb bl",
                b"    add rax, " + hex(stack_size - red_zone_size).encode("ascii"),
                b"    cmp rax, rsp",
                b"    seta bh",
                b"    add bl, bh",
                b"    cmp bl, 2",
                b"    je abisan_fail_mov_below_rsp",
                b"    pop rbx",
                b"    pop rax",
                b"    popfq",
            )
        )
        + b"\n"
    )


def generate_reg_taint_check(
    line: bytes, insn: CsInsn, r: int, red_zone_size: int
) -> bytes:

    if insn.op_count(capstone.CS_OP_MEM) > 0 and insn.mnemonic == "mov":
        # r is source &&
        # A memory operand exists, so it must be the destination
        # So, we are moving into memory
        # If:
        #     r fails the taintedness check &&
        #     destination is not in stack
        # Then call the fail taint check func

        return (
            b"\n".join(
                (
                    b"    pushfq",
                    b"    push rax",
                    b"    push rbx",
                    b"    lea rbx, " + get_memory_operand(line),
                    b"    " + insn.mnemonic.encode("ascii") + b" rax, rbx",
                    b"    add rbx, " + hex(red_zone_size).encode("ascii"),
                    b"    cmp rbx, rsp",
                    b"    setb bl",
                    f"    lea rax , offset abisan_taint_state[rip + {cs_to_taint_idx(r)}]".encode(
                        "ascii"
                    ),
                    b"    mov al, byte ptr [rax]",
                    b"    cmp al, 0",
                    b"    setne bh",
                    b"    add bl, bh",
                    b"    cmp bl, 2",
                    f"    je abisan_fail_taint_{cs.reg_name(r)}".encode(),
                    b"    pop rbx",
                    b"    pop rax",
                    b"    popfq",
                )
            )
            + b"\n"
        )

    return (
        b"\n".join(
            (
                b"    pushfq",
                b"    push rax",
                f"    lea rax, offset abisan_taint_state[rip + {cs_to_taint_idx(r)}]".encode(
                    "ascii"
                ),
                b"    mov al, byte ptr [rax]",
                b"    cmp al, 0",
                f"    jne abisan_fail_taint_{cs.reg_name(r)}".encode(),
                b"    pop rax",
                b"    popfq",
            )
        )
        + b"\n"
    )


def generate_generic_reg_taint_update(r: int) -> bytes:
    return (
        b"\n".join(
            (
                b"    push rax",
                f"    lea rax, offset abisan_taint_state[rip + {cs_to_taint_idx(r)}]".encode(
                    "ascii"
                ),
                b"    mov byte ptr [rax], 0",
                b"    pop rax",
            )
        )
        + b"\n"
    )


def generate_cmov_reg_taint_update(line: bytes, insn: CsInsn, r: int) -> bytes:
    return (
        b"\n".join(
            (
                b"    push rax",
                b"    push rbx",
                b"     push rcx",
                f"    lea rax, offset abisan_taint_state[rip + {cs_to_taint_idx(r)}]".encode(
                    "ascii"
                ),
                b"    mov bl, byte ptr [rax]",
                b"    mov rcx, 0",
                b"    " + insn.mnemonic.encode("ascii") + b" rbx, rcx",
                b"    mov byte ptr [rax], bl",
                b"    pop rcx",
                b"    pop rbx",
                b"    pop rax",
            )
        )
        + b"\n"
    )


def generate_taint_after_call() -> bytes:
    # Taint everything that could have been clobbered in a call
    return (
        b"\n".join(
            (
                b"    push rdi",
                b"    lea rdi, byte ptr offset abisan_taint_state[rip]",
                f"    mov byte ptr [rdi + {TAINT_STATE_RAX}], 0".encode(),  # TODO: This should be tainted for void functions
                f"    mov byte ptr [rdi + {TAINT_STATE_RCX}], 1".encode(),
                f"    mov byte ptr [rdi + {TAINT_STATE_RDX}], 1".encode(),  # TODO: This shouldn't be tainted for functions that return in rdx:rax
                f"    mov byte ptr [rdi + {TAINT_STATE_RDI}], 1".encode(),
                f"    mov byte ptr [rdi + {TAINT_STATE_RSI}], 1".encode(),
                f"    mov byte ptr [rdi + {TAINT_STATE_R8}], 1".encode(),
                f"    mov byte ptr [rdi + {TAINT_STATE_R9}], 1".encode(),
                f"    mov byte ptr [rdi + {TAINT_STATE_R10}], 1".encode(),
                f"    mov byte ptr [rdi + {TAINT_STATE_R11}], 1".encode(),
                b"    pop rdi",
            )
        )
        + b"\n"
    )


def main() -> None:
    if len(sys.argv) < 2 or len(sys.argv) > 4:
        print(
            f"Usage: python3 {sys.argv[0]} <assembly_file> [red_zone_size] [stack_size]",
            file=sys.stderr,
        )
        sys.exit(1)

    red_zone_size: int = INIT_RED_ZONE_SIZE
    stack_size: int = INIT_STACK_SIZE
    if len(sys.argv) >= 3:
        red_zone_size = int(sys.argv[2], 16)
    if len(sys.argv) >= 4:
        stack_size = int(sys.argv[3], 16)

    # Improper arguments when:
    # - any sizes are < 0x8 (size of address in 64bit)
    # - red zone is larger than the size of the stack
    # - any sizes are not multiples of 8 (aligned)
    # TODO: Support 32bit
    if (
        red_zone_size < 8
        or red_zone_size >= stack_size
        or red_zone_size % 8 != 0
        or stack_size % 8 != 0
    ):
        print(
            f"Tunables must be greater than the size of an address, stack aligned, and red zone must be smaller than the stack. Red Zone Size {red_zone_size} or Stack Size {stack_size} is invalid.",
            file=sys.stderr,
        )
        sys.exit(1)

    input_file_name: str = sys.argv[1]
    _, input_file_name_suffix = input_file_name.rsplit(".", maxsplit=1)
    intermediate_file_name: str = (
        f"{input_file_name}.abisan.intermediate.{input_file_name_suffix}"
    )
    intermediate_object_file_name: str = f"{intermediate_file_name}.o"

    with open(sys.argv[1], "rb") as f:
        source_code: bytes = f.read()

    lines: list[bytes] = source_code.splitlines(keepends=True)

    # Add a global label before every instruction
    with open(intermediate_file_name, "xb") as f:
        instruction_line_numbers: dict[bytes, int] = {}
        for i, line in enumerate(map(bytes.rstrip, map(remove_comment, lines))):
            if is_instruction(line):
                label_name: bytes = f"abisan_intermediate_{i}".encode("ascii")
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

    output_file_name: str = f"{input_file_name}.abisan.{input_file_name_suffix}"

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
                    if insn.mnemonic.startswith("cmov"):
                        f.write(
                            generate_cmov_instrumentation(
                                line, insn, red_zone_size, stack_size
                            )
                        )
                    else:
                        f.write(
                            generate_generic_memory_instrumentation(
                                line, red_zone_size, stack_size
                            )
                        )

                if needs_taint_check_for_read(insn):
                    for r in get_registers_read(insn):
                        f.write(generate_reg_taint_check(line, insn, r, red_zone_size))

                for r in get_registers_written(insn):
                    if insn.mnemonic.startswith("cmov"):
                        f.write(generate_cmov_reg_taint_update(line, insn, r))
                    else:
                        f.write(generate_generic_reg_taint_update(r))

            f.write(line + b"\n")

            if insn is not None and insn.mnemonic.startswith("call"):
                f.write(generate_taint_after_call())

            if get_label_name(line) in global_symbols:
                f.write(b"    call abisan_function_entry\n")


if __name__ == "__main__":
    main()

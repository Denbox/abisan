import dataclasses
import os
import subprocess
import sys
import re

import capstone  # type: ignore
from capstone import Cs, CsInsn, x86_const
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection

from instruction import (
    Instruction,
    Register,
    EffectiveAddress,
    Immediate,
    EAWidth,
    Label,
    JumpTarget,
)


cs: Cs = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True

TAINT_STATE_RAX: int = 0
TAINT_STATE_RBX: int = 1
TAINT_STATE_RCX: int = 2
TAINT_STATE_RDX: int = 3
TAINT_STATE_RDI: int = 4
TAINT_STATE_RSI: int = 5
TAINT_STATE_R8: int = 6
TAINT_STATE_R9: int = 7
TAINT_STATE_R10: int = 8
TAINT_STATE_R11: int = 9
TAINT_STATE_R12: int = 10
TAINT_STATE_R13: int = 11
TAINT_STATE_R14: int = 12
TAINT_STATE_R15: int = 13
TAINT_STATE_RBP: int = 14
TAINT_STATE_EFLAGS: int = 15

REDZONE_SIZE: int = 0x80


@dataclasses.dataclass
class Config:
    redzone_enabled: bool
    stack_size: int


# Expects Environment variables to be semicolon separated
# REDZONE_ENABLED = int
# STACK_SIZE = int
def parse_tunable_envs(tunables: str):
    redzone_enabled: bool = False
    stack_size: int = 0x800000

    if len(tunables) > 0:
        if tunables.startswith("REDZONE_ENABLED="):
            tunables = tunables[len("REDZONE_ENABLED=") :]
            redzone_enabled_match: re.Match[str] | None = re.match(
                r"\A(?P<value>[0-9]+)", tunables
            )
            assert redzone_enabled_match is not None

            redzone_enabled = bool(int(redzone_enabled_match["value"]))

            tunables = tunables[len(redzone_enabled_match["value"]) :]

            if tunables.startswith(";STACK_SIZE="):
                tunables = tunables[len(";STACK_SIZE=") :]
                stack_size_match: re.Match[str] | None = re.match(
                    r"\A(?P<value>[0-9]+)", tunables
                )
                assert stack_size_match is not None
                stack_size = int(stack_size_match["value"])

    return Config(redzone_enabled, stack_size)


def get_memory_operand(line: bytes, insn: CsInsn) -> EffectiveAddress:

    syntax = "att"
    tokens: list[bytes] = line.split(maxsplit=1)
    assert len(tokens) == 2
    
    mnemonic: bytes = tokens[0].lower()
    assert mnemonic != b"lea"

    # TODO: Support AT&T syntax
    # TODO: Support single-quoted [ and ,.
    if "intel" in syntax:
        for operand in (token.strip() for token in tokens[1].split(b",")):
            if b"[" in operand:
                return EffectiveAddress.deserialize_intel(operand)
    elif "att" in syntax:
        # TODO: handle Effective Address with only displacement (no parenthesis)
        offset_match: re.Match[str] | None = re.match(
            rf"(?:{tokens[0].decode('ascii')}|,)\s+(?P<offset>[^,]+\(.*?\))", line.lstrip().decode("ascii")
        )
        if offset_match is not None:
            # Pass to effective address: b"width memory_operand"
            width_mem_operand: bytes = b" ".join((
                tokens[0].lstrip()[len(insn.mnemonic):len(insn.mnemonic)+1],
                offset_match["offset"].encode("ascii")
            ))
            return EffectiveAddress.deserialize_att(width_mem_operand)
    print(line)
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
    return set(filter(lambda r: r not in _UNUSED_REGISTERS, result))


def get_registers_written(insn: CsInsn) -> set[int]:
    result: set[int] = set()
    result.update(insn.regs_write)
    for op in insn.operands:
        if op.type == capstone.CS_OP_REG and op.access & capstone.CS_AC_WRITE:
            result.add(op.reg)

    return set(filter(lambda r: r not in _UNUSED_REGISTERS, result))


# bitwise negation of 8bit int
def bitwise_neg8(i: int) -> int:
    return int("".join("1" if bit == "0" else "0" for bit in bin(i)[2:].zfill(8)), 2)


def get_taint_mask(r: int) -> int:
    match r:
        case (
            x86_const.X86_REG_RAX
            | x86_const.X86_REG_RBX
            | x86_const.X86_REG_RCX
            | x86_const.X86_REG_RDX
            | x86_const.X86_REG_RSI
            | x86_const.X86_REG_RDI
            | x86_const.X86_REG_RBP
            | x86_const.X86_REG_RSP
            | x86_const.X86_REG_R8
            | x86_const.X86_REG_R9
            | x86_const.X86_REG_R10
            | x86_const.X86_REG_R11
            | x86_const.X86_REG_R12
            | x86_const.X86_REG_R13
            | x86_const.X86_REG_R14
            | x86_const.X86_REG_R15
            | x86_const.X86_REG_RIP
            | x86_const.X86_REG_EFLAGS
        ):  # 64 bit regs
            return 0xFF
        case (
            x86_const.X86_REG_EAX
            | x86_const.X86_REG_EBX
            | x86_const.X86_REG_ECX
            | x86_const.X86_REG_EDX
            | x86_const.X86_REG_ESI
            | x86_const.X86_REG_EDI
            | x86_const.X86_REG_EBP
            | x86_const.X86_REG_ESP
            | x86_const.X86_REG_R8D
            | x86_const.X86_REG_R9D
            | x86_const.X86_REG_R10D
            | x86_const.X86_REG_R11D
            | x86_const.X86_REG_R12D
            | x86_const.X86_REG_R13D
            | x86_const.X86_REG_R14D
            | x86_const.X86_REG_R15D
            | x86_const.X86_REG_EIP
        ):  # 32 bit regs
            return 0x0F
        case (
            x86_const.X86_REG_AX
            | x86_const.X86_REG_BX
            | x86_const.X86_REG_CX
            | x86_const.X86_REG_DX
            | x86_const.X86_REG_SI
            | x86_const.X86_REG_DI
            | x86_const.X86_REG_BP
            | x86_const.X86_REG_SP
            | x86_const.X86_REG_R8W
            | x86_const.X86_REG_R9W
            | x86_const.X86_REG_R10W
            | x86_const.X86_REG_R11W
            | x86_const.X86_REG_R12W
            | x86_const.X86_REG_R13W
            | x86_const.X86_REG_R14W
            | x86_const.X86_REG_R15W
            | x86_const.X86_REG_IP
        ):  # 16 bit regs
            return 0x03
        case (
            x86_const.X86_REG_AH
            | x86_const.X86_REG_BH
            | x86_const.X86_REG_CH
            | x86_const.X86_REG_DH
        ):  # high 8 bit regs
            return 0x02
        case (
            x86_const.X86_REG_AL
            | x86_const.X86_REG_BL
            | x86_const.X86_REG_CL
            | x86_const.X86_REG_DL
            | x86_const.X86_REG_SIL
            | x86_const.X86_REG_DIL
            | x86_const.X86_REG_BPL
            | x86_const.X86_REG_SPL
            | x86_const.X86_REG_R8B
            | x86_const.X86_REG_R9B
            | x86_const.X86_REG_R10B
            | x86_const.X86_REG_R11B
            | x86_const.X86_REG_R12B
            | x86_const.X86_REG_R13B
            | x86_const.X86_REG_R14B
            | x86_const.X86_REG_R15B
        ):  # low 8 bit regs
            return 0x01

    print("Unsupported register {cs.reg_name(r)}", file=sys.stderr)
    sys.exit(1)


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


def generate_cmov_instrumentation(line: bytes, insn: CsInsn, config: Config) -> bytes:
        instructions: list[Instruction] = [
        Instruction(b"pushfq"),
        Instruction(b"push", Register(b"rax")),
        Instruction(b"push", Register(b"rbx")),
        Instruction(
            b"lea",
            Register(b"rbx"),
            EffectiveAddress.deserialize_intel(get_memory_operand(line))
        ),
        Instruction(b"mov", Register(b"rax"), Register(b"rsp")),
        *(
            [
                Instruction(
                    b"add",
                    Register(b"rax"),
                    Immediate(hex(REDZONE_SIZE).encode("ascii")),
                )
            ]
            if config.redzone_enabled
            else []
        ),
        Instruction(b"cmp", Register(b"rax"), Register(b"rsp")),
        Instruction(b"setb", Register(b"bl")),
        Instruction(
            b"add",
            Register(b"rax"),
            Immediate(
                hex(
                    config.stack_size - (REDZONE_SIZE if config.redzone_enabled else 0)
                ).encode("ascii")
            ),
        ),
        Instruction(b"cmp", Register(b"rax"), Register(b"rsp")),
        Instruction(b"seta", Register(b"bh")),
        Instruction(b"add", Register(b"bl"), Register(b"bh")),
        Instruction(b"cmp", Register(b"bl"), Immediate(b"2")),
        Instruction(b"je", JumpTarget(Label(b"abisan_fail_mov_below_rsp"))),
        Instruction(b"pop", Register(b"rbx")),
        Instruction(b"pop", Register(b"rax")),
        Instruction(b"popfq"),
        ]
        return b"\n".join(map(Instruction.serialize_intel, instructions)) + b"\n"


def generate_generic_memory_instrumentation(line: bytes, insn: CsInsn, config: Config) -> bytes:
    instructions: list[Instruction] = [
        Instruction(b"pushfq"),
        Instruction(b"push", Register(b"rax")),
        Instruction(b"push", Register(b"rbx")),
        Instruction(
            b"lea",
            Register(b"rax"),
            get_memory_operand(line, insn),
        ),
        *(
            [
                Instruction(
                    b"add",
                    Register(b"rax"),
                    Immediate(hex(REDZONE_SIZE).encode("ascii")),
                )
            ]
            if config.redzone_enabled
            else []
        ),
        Instruction(b"cmp", Register(b"rax"), Register(b"rsp")),
        Instruction(b"setb", Register(b"bl")),
        Instruction(
            b"add",
            Register(b"rax"),
            Immediate(
                hex(
                    config.stack_size - (REDZONE_SIZE if config.redzone_enabled else 0)
                ).encode("ascii")
            ),
        ),
        Instruction(b"cmp", Register(b"rax"), Register(b"rsp")),
        Instruction(b"seta", Register(b"bh")),
        Instruction(b"add", Register(b"bl"), Register(b"bh")),
        Instruction(b"cmp", Register(b"bl"), Immediate(b"2")),
        Instruction(b"je", JumpTarget(Label(b"abisan_fail_mov_below_rsp"))),
        Instruction(b"pop", Register(b"rbx")),
        Instruction(b"pop", Register(b"rax")),
        Instruction(b"popfq"),
    ]

    return b"\n".join(map(Instruction.serialize_intel, instructions)) + b"\n"


def generate_reg_taint_check(
    line: bytes, insn: CsInsn, r: int, config: Config
) -> bytes:
    instructions: list[Instruction] = []

    if insn.op_count(capstone.CS_OP_MEM) > 0 and insn.mnemonic == "mov":
        # r is source &&
        # A memory operand exists, so it must be the destination
        # So, we are moving into memory
        # If:
        #     r fails the taintedness check &&
        #     destination is not in stack
        # Then call the fail taint check func

        # TODO: Support cmov?
        instructions = [
            Instruction(
                b"pushfq",
            ),
            Instruction(b"push", Register(b"rax")),
            Instruction(b"push", Register(b"rbx")),
            Instruction(
                b"lea",
                Register(b"rbx"),
                get_memory_operand(line, insn),
            ),
            Instruction(
                insn.mnemonic.encode("ascii"), Register(b"rax"), Register(b"rbx")
            ),
            *(
                [
                    Instruction(
                        b"add",
                        Register(b"rbx"),
                        Immediate(hex(REDZONE_SIZE).encode("ascii")),
                    )
                ]
                if config.redzone_enabled
                else []
            ),
            Instruction(b"cmp", Register(b"rbx"), Register(b"rsp")),
            Instruction(b"setb", Register(b"bl")),
            Instruction(
                b"lea",
                Register(b"rax"),
                EffectiveAddress(
                    offset=Label(b"abisan_taint_state"),
                    base=Register(b"rip"),
                    displacement=Immediate(
                        str(cs_to_taint_idx(register_normalize(r))).encode("ascii")
                    ),
                ),
            ),
            Instruction(
                b"mov",
                Register(b"al"),
                EffectiveAddress(width=EAWidth.BYTE_PTR, base=Register(b"rax")),
            ),
            Instruction(
                b"and",
                Register(b"al"),
                Immediate(hex(get_taint_mask(r)).encode("ascii")),
            ),
            Instruction(b"cmp", Register(b"al"), Immediate(b"0")),
            Instruction(b"setne", Register(b"bh")),
            Instruction(b"add", Register(b"bl"), Register(b"bh")),
            Instruction(b"cmp", Register(b"bl"), Immediate(b"2")),
            Instruction(
                b"je",
                JumpTarget(
                    Label(b"abisan_fail_taint_" + cs.reg_name(r).encode("ascii"))
                ),
            ),
            Instruction(b"pop", Register(b"rbx")),
            Instruction(b"pop", Register(b"rax")),
            Instruction(
                b"popfq",
            ),
        ]
    else:
        instructions = [
            Instruction(
                b"pushfq",
            ),
            Instruction(b"push", Register(b"rax")),
            Instruction(
                b"lea",
                Register(b"rax"),
                EffectiveAddress(
                    offset=Label(b"abisan_taint_state"),
                    base=Register(b"rip"),
                    displacement=Immediate(
                        str(cs_to_taint_idx(register_normalize(r))).encode("ascii")
                    ),
                ),
            ),
            Instruction(
                b"mov",
                Register(b"al"),
                EffectiveAddress(width=EAWidth.BYTE_PTR, base=Register(b"rax")),
            ),
            Instruction(
                b"and",
                Register(b"al"),
                Immediate(hex(get_taint_mask(r)).encode("ascii")),
            ),
            Instruction(b"cmp", Register(b"al"), Immediate(b"0")),
            Instruction(
                b"jne",
                JumpTarget(
                    Label(b"abisan_fail_taint_" + cs.reg_name(r).encode("ascii"))
                ),
            ),
            Instruction(b"pop", Register(b"rax")),
            Instruction(
                b"popfq",
            ),
        ]

    return b"\n".join(map(Instruction.serialize_intel, instructions)) + b"\n"


def generate_generic_reg_taint_update(r: int) -> bytes:
    instructions: list[Instruction] = [
        Instruction(b"push", Register(b"rax")),
        Instruction(
            b"lea",
            Register(b"rax"),
            EffectiveAddress(
                offset=Label(b"abisan_taint_state"),
                base=Register(b"rip"),
                displacement=Immediate(
                    str(cs_to_taint_idx(register_normalize(r))).encode("ascii")
                ),
            ),
        ),
        Instruction(
            b"and",
            EffectiveAddress(width=EAWidth.BYTE_PTR, base=Register(b"rax")),
            Immediate(str(bitwise_neg8(get_taint_mask(r))).encode("ascii")),
        ),
        Instruction(b"pop", Register(b"rax")),
    ]

    return b"\n".join(map(Instruction.serialize_intel, instructions)) + b"\n"


def generate_cmov_reg_taint_update(insn: CsInsn, r: int) -> bytes:
    instructions: list[Instruction] = [
        Instruction(b"push", Register(b"rax")),
        Instruction(b"push", Register(b"rbx")),
        Instruction(b"push", Register(b"rcx")),
        Instruction(b"pushfq"),
        Instruction(
            b"lea",
            Register(b"rax"),
            EffectiveAddress(
                offset=Label(b"abisan_taint_state"),
                base=Register(b"rip"),
                displacement=Immediate(
                    str(cs_to_taint_idx(register_normalize(r))).encode("ascii")
                )
            )
        ),
        Instruction(
            b"mov",
            Register(b"bl"),
            EffectiveAddress(width=EAWidth.BYTE_PTR, base=Register(b"rax")),
        ),
        Instruction(b"mov", 
            Register(b"cl"), 
            Register(b"bl")
        ),
        Instruction(
            b"and",
            Register(b"cl"),
            Immediate(str(bitwise_neg8(get_taint_mask(r))).encode("ascii")),
        ),
        Instruction(
            insn.mnemonic.encode("ascii"), Register(b"rbx"), Register(b"rcx")
        ),
        Instruction(
            b"mov",
            EffectiveAddress(width=EAWidth.BYTE_PTR, base=Register(b"rax")),
            Register(b"bl"),
        ),
        Instruction(b"popfq"),
        Instruction(b"pop", Register(b"rcx")),
        Instruction(b"pop", Register(b"rbx")),
        Instruction(b"pop", Register(b"rax")),
    ]
    return b"\n".join(map(Instruction.serialize_intel, instructions)) + b"\n"


def generate_taint_after_call() -> bytes:
    # Taint everything that could have been clobbered in a call
    return (
        b"\n".join(
            (
                b"    push rdi",
                b"    lea rdi, byte ptr offset abisan_taint_state[rip]",
                f"    mov byte ptr [rdi + {TAINT_STATE_RAX}], 0".encode(
                    "ascii"
                ),  # TODO: This should be tainted for void functions
                f"    mov byte ptr [rdi + {TAINT_STATE_RCX}], 0xff".encode("ascii"),
                f"    mov byte ptr [rdi + {TAINT_STATE_RDX}], 0xff".encode(
                    "ascii"
                ),  # TODO: This shouldn't be tainted for functions that return in rdx:rax
                f"    mov byte ptr [rdi + {TAINT_STATE_RDI}], 0xff".encode("ascii"),
                f"    mov byte ptr [rdi + {TAINT_STATE_RSI}], 0xff".encode("ascii"),
                f"    mov byte ptr [rdi + {TAINT_STATE_R8}], 0xff".encode("ascii"),
                f"    mov byte ptr [rdi + {TAINT_STATE_R9}], 0xff".encode("ascii"),
                f"    mov byte ptr [rdi + {TAINT_STATE_R10}], 0xff".encode("ascii"),
                f"    mov byte ptr [rdi + {TAINT_STATE_R11}], 0xff".encode("ascii"),
                b"    pop rdi",
            )
        )
        + b"\n"
    )


def main() -> None:
    if len(sys.argv) != 2:
        print(
            f"Usage: python3 {sys.argv[0]} <assembly_file>",
            file=sys.stderr,
        )
        sys.exit(1)

    tunables: str = os.environ.get("ABISAN_TUNABLES", "")
    config: Config = parse_tunable_envs(tunables)

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
                print("mnem:",insn.mnemonic)
                print(get_memory_operand(line,insn))
                registers_read: set[int] = get_registers_read(insn)
                registers_written: set[int] = get_registers_written(insn)
                if insn.op_count(capstone.CS_OP_MEM) > 0 and insn.mnemonic != "lea":
                    if insn.mnemonic.startswith("cmov"):
                        f.write(generate_cmov_instrumentation(line, insn, config))
                    else:
                        f.write(generate_generic_memory_instrumentation(line, insn, config))

                if needs_taint_check_for_read(insn):
                    for r in get_registers_read(insn):
                        f.write(generate_reg_taint_check(line, insn, r, config))

                for r in get_registers_written(insn):
                    if insn.mnemonic.startswith("cmov"):
                        f.write(generate_cmov_reg_taint_update(insn, r))
                    else:
                        f.write(generate_generic_reg_taint_update(r))

            f.write(line + b"\n")

            if insn is not None and insn.mnemonic.startswith("call"):
                f.write(generate_taint_after_call())

            if get_label_name(line) in global_symbols:
                f.write(b"    call abisan_function_entry\n")


if __name__ == "__main__":
    main()

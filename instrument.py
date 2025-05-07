import dataclasses
import os
import subprocess
import sys
import re

import capstone  # type: ignore
from capstone import Cs, CsInsn, x86_const
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import Section, SymbolTableSection

# TODO: support segment registers

from instruction import (
    Instruction,
    Register,
    EffectiveAddress,
    Immediate,
    EAWidth,
    Label,
    JumpTarget,
)

# TODO: no taint check on rsp
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
REDZONE_ENABLED_ENV_NAME: str = "ABISAN_TUNABLES_REDZONE_ENABLED"
STACK_SIZE_ENV_NAME: str = "ABISAN_TUNABLES_STACK_SIZE"
SYNTAX_ENV_NAME: str = "ABISAN_TUNABLES_SYNTAX"
NUM_ENVS: int = 3

# Non-crucial fluff created by compilers besides gcc which is not supported in the gnu assembler
AS_UNSUPPORTED: list[bytes] = [b".addrsig"]


@dataclasses.dataclass
class Config:
    redzone_enabled: bool
    stack_size: int
    syntax: str


# tunables is a list of environment variable values in the following order:
# 0: REDZONE_ENABLED
# 1: STACK_SIZE
# 2: SYNTAX
def parse_tunable_envs(tunables: list[str]):
    redzone_enabled: bool = False
    stack_size: int = 0x800000
    syntax: str = "intel"

    if len(tunables) == NUM_ENVS:

        redzone_enabled_match: re.Match[str] | None = re.match(
            r"\A(?P<value>[0-9]+)", tunables[0]
        )
        if redzone_enabled_match is not None:
            redzone_enabled = bool(int(redzone_enabled_match["value"]))

        stack_size_match: re.Match[str] | None = re.match(
            r"\A(?P<value>[0-9]+)", tunables[1]
        )
        if stack_size_match is not None:
            stack_size = int(stack_size_match["value"])

        syntax_match: re.Match[str] | None = re.match(
            r"\A(?P<value>(intel)|(att))", tunables[2]
        )
        if syntax_match is not None:
            syntax = syntax_match["value"]

    return Config(redzone_enabled, stack_size, syntax)


def serialize(instructions: list[Instruction], config: Config) -> bytes:
    if config.syntax == "intel":
        return b"\n".join(map(Instruction.serialize_intel, instructions)) + b"\n"
    elif config.syntax == "att":
        return b"\n".join(map(Instruction.serialize_att, instructions)) + b"\n"
    else:
        raise ValueError("Invalid syntax provided")


def get_memory_operand(
    line: bytes, insn: CsInsn, config: Config
) -> EffectiveAddress | None:

    tokens: list[bytes] = line.split(maxsplit=1)
    assert len(tokens) == 2

    mnemonic: bytes = tokens[0].lower()
    assert mnemonic != b"lea"

    # TODO: Support single-quoted [ and , and ptr and offset
    # TODO: support rip relative movs
    if config.syntax == "intel":
        for operand in (token.strip() for token in tokens[1].split(b",")):
            if b"[" in operand or b":" in operand:

                # How should we handle instructions like:
                # call [qword ptr 48[rax]]
                while operand.startswith(b"[") and operand.endswith(b"]"):
                    operand = operand.strip(b"[]")

                # What we need:
                # Where in string substring was found
                # Length of substring found
                prefix_signal_start: int
                prefix_signaler: bytes
                lower_operand: bytes = operand.lower()
                prefix_signal_start, prefix_signaler = next(
                    (
                        (lower_operand.find(string), string)
                        for string in [b"ptr", b"offset"]
                        if string in lower_operand
                    ),
                    (-1, b""),
                )

                if prefix_signal_start >= 0:
                    return EffectiveAddress.deserialize_intel(
                        operand[: prefix_signal_start + len(prefix_signaler)],
                        operand[prefix_signal_start + len(prefix_signaler) :],
                    )
                else:
                    return EffectiveAddress.deserialize_intel(b"", operand)

        raise ValueError("Invalid intel memory operand: " + line.decode("ascii"))

    elif config.syntax == "att":
        # Remove mnemonic
        # Starting left to right, try and parse as a memory operand, if we reach the potential memory operand, yay!
        # Otherwise, consume everything up until the next comma

        mem_operand: bytes = line.lstrip()[len(mnemonic) :]
        EA: EffectiveAddress | None
        width: bytes = tokens[0].lstrip()[len(insn.mnemonic) : len(insn.mnemonic) + 1]

        while (
            EA := EffectiveAddress.deserialize_att(width, mem_operand.lstrip())
        ) is None:
            if b"," in mem_operand and not mem_operand.endswith(b","):
                before_first_comma = mem_operand.split(b",")[0]
                mem_operand = mem_operand[len(before_first_comma) + 1 :]
            else:  # No operands remaining
                assert False
        return EA
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
    m: re.Match[bytes] | None = re.match(rb"\A(?P<label_name>[0-9a-zA-Z_.]+):", line)
    if m is not None:
        return m["label_name"]
    return None


def is_label(line: bytes) -> bool:
    return get_label_name(line) is not None


def is_instruction(line: bytes) -> bool:
    line = line.lstrip()
    return len(line) > 0 and not line.startswith(b".") and not is_label(line)


def get_intermediate_labels(elf_file: ELFFile) -> dict[bytes, CsInsn]:
    result: list[tuple[str, int, int]] = []
    for i in range(elf_file.num_sections()):
        section: Section = elf_file.get_section(i)
        if isinstance(section, SymbolTableSection):
            result += [
                (symbol.name, symbol.entry["st_value"], symbol.entry["st_shndx"])
                for symbol in section.iter_symbols()
                if symbol.name.startswith("abisan_intermediate")
            ]
    return {
        name.encode("ascii"): next(
            cs.disasm(elf_file.get_section(section).data()[offset:], offset=0, count=1)
        )
        for name, offset, section in result
    }


_UNUSED_REGISTERS: set[int] = {
    x86_const.X86_REG_RIP,
    x86_const.X86_REG_RSP,
    x86_const.X86_REG_FS,
    x86_const.X86_REG_GS,
    x86_const.X86_REG_ES,
    x86_const.X86_REG_SS,
    x86_const.X86_REG_DS,
    x86_const.X86_REG_CS,
    x86_const.X86_REG_EFLAGS,
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

    if len(reg_ops) > 0 and all(
        register_normalize(reg) in _UNUSED_REGISTERS for reg in reg_ops
    ):
        return False

    return True


def needs_taint_update_for_write(insn: CsInsn) -> bool:
    reg_ops: set[int] = get_registers_written(insn)

    if len(reg_ops) <= 0:
        return False

    if all(register_normalize(reg) in _UNUSED_REGISTERS for reg in reg_ops):
        return False

    return True


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
            | x86_const.X86_REG_ZMM0
            | x86_const.X86_REG_ZMM1
            | x86_const.X86_REG_ZMM2
            | x86_const.X86_REG_ZMM3
            | x86_const.X86_REG_ZMM4
            | x86_const.X86_REG_ZMM5
            | x86_const.X86_REG_ZMM6
            | x86_const.X86_REG_ZMM7
            | x86_const.X86_REG_ZMM8
            | x86_const.X86_REG_ZMM9
            | x86_const.X86_REG_ZMM10
            | x86_const.X86_REG_ZMM11
            | x86_const.X86_REG_ZMM12
            | x86_const.X86_REG_ZMM13
            | x86_const.X86_REG_ZMM14
            | x86_const.X86_REG_ZMM15
            | x86_const.X86_REG_ZMM16
            | x86_const.X86_REG_ZMM17
            | x86_const.X86_REG_ZMM18
            | x86_const.X86_REG_ZMM19
            | x86_const.X86_REG_ZMM20
            | x86_const.X86_REG_ZMM21
            | x86_const.X86_REG_ZMM22
            | x86_const.X86_REG_ZMM23
            | x86_const.X86_REG_ZMM24
            | x86_const.X86_REG_ZMM25
            | x86_const.X86_REG_ZMM26
            | x86_const.X86_REG_ZMM27
            | x86_const.X86_REG_ZMM28
            | x86_const.X86_REG_ZMM29
            | x86_const.X86_REG_ZMM30
            | x86_const.X86_REG_ZMM31
        ):  # 64 & 512 bit regs
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
            | x86_const.X86_REG_YMM0
            | x86_const.X86_REG_YMM1
            | x86_const.X86_REG_YMM2
            | x86_const.X86_REG_YMM3
            | x86_const.X86_REG_YMM4
            | x86_const.X86_REG_YMM5
            | x86_const.X86_REG_YMM6
            | x86_const.X86_REG_YMM7
            | x86_const.X86_REG_YMM8
            | x86_const.X86_REG_YMM9
            | x86_const.X86_REG_YMM10
            | x86_const.X86_REG_YMM11
            | x86_const.X86_REG_YMM12
            | x86_const.X86_REG_YMM13
            | x86_const.X86_REG_YMM14
            | x86_const.X86_REG_YMM15
            | x86_const.X86_REG_YMM16
            | x86_const.X86_REG_YMM17
            | x86_const.X86_REG_YMM18
            | x86_const.X86_REG_YMM19
            | x86_const.X86_REG_YMM20
            | x86_const.X86_REG_YMM21
            | x86_const.X86_REG_YMM22
            | x86_const.X86_REG_YMM23
            | x86_const.X86_REG_YMM24
            | x86_const.X86_REG_YMM25
            | x86_const.X86_REG_YMM26
            | x86_const.X86_REG_YMM27
            | x86_const.X86_REG_YMM28
            | x86_const.X86_REG_YMM29
            | x86_const.X86_REG_YMM30
            | x86_const.X86_REG_YMM31
        ):  # 32 & 256 bit regs
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
            | x86_const.X86_REG_XMM0
            | x86_const.X86_REG_XMM1
            | x86_const.X86_REG_XMM2
            | x86_const.X86_REG_XMM3
            | x86_const.X86_REG_XMM4
            | x86_const.X86_REG_XMM5
            | x86_const.X86_REG_XMM6
            | x86_const.X86_REG_XMM7
            | x86_const.X86_REG_XMM8
            | x86_const.X86_REG_XMM9
            | x86_const.X86_REG_XMM10
            | x86_const.X86_REG_XMM11
            | x86_const.X86_REG_XMM12
            | x86_const.X86_REG_XMM13
            | x86_const.X86_REG_XMM14
            | x86_const.X86_REG_XMM15
            | x86_const.X86_REG_XMM16
            | x86_const.X86_REG_XMM17
            | x86_const.X86_REG_XMM18
            | x86_const.X86_REG_XMM19
            | x86_const.X86_REG_XMM20
            | x86_const.X86_REG_XMM21
            | x86_const.X86_REG_XMM22
            | x86_const.X86_REG_XMM23
            | x86_const.X86_REG_XMM24
            | x86_const.X86_REG_XMM25
            | x86_const.X86_REG_XMM26
            | x86_const.X86_REG_XMM27
            | x86_const.X86_REG_XMM28
            | x86_const.X86_REG_XMM29
            | x86_const.X86_REG_XMM30
            | x86_const.X86_REG_XMM31
        ):  # 16 & 128 bit regs
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

    print(f"Unsupported register {cs.reg_name(r)} in get_taint_mask", file=sys.stderr)
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

        case x86_const.X86_REG_ZMM0 | x86_const.X86_REG_YMM0 | x86_const.X86_REG_XMM0:
            return x86_const.X86_REG_ZMM0

        case x86_const.X86_REG_ZMM1 | x86_const.X86_REG_YMM1 | x86_const.X86_REG_XMM1:
            return x86_const.X86_REG_ZMM1

        case x86_const.X86_REG_ZMM2 | x86_const.X86_REG_YMM2 | x86_const.X86_REG_XMM2:
            return x86_const.X86_REG_ZMM2

        case x86_const.X86_REG_ZMM3 | x86_const.X86_REG_YMM3 | x86_const.X86_REG_XMM3:
            return x86_const.X86_REG_ZMM3

        case x86_const.X86_REG_ZMM4 | x86_const.X86_REG_YMM4 | x86_const.X86_REG_XMM4:
            return x86_const.X86_REG_ZMM4

        case x86_const.X86_REG_ZMM5 | x86_const.X86_REG_YMM5 | x86_const.X86_REG_XMM5:
            return x86_const.X86_REG_ZMM5

        case x86_const.X86_REG_ZMM6 | x86_const.X86_REG_YMM6 | x86_const.X86_REG_XMM6:
            return x86_const.X86_REG_ZMM6

        case x86_const.X86_REG_ZMM7 | x86_const.X86_REG_YMM7 | x86_const.X86_REG_XMM7:
            return x86_const.X86_REG_ZMM7

        case x86_const.X86_REG_ZMM8 | x86_const.X86_REG_YMM8 | x86_const.X86_REG_XMM8:
            return x86_const.X86_REG_ZMM8

        case x86_const.X86_REG_ZMM9 | x86_const.X86_REG_YMM9 | x86_const.X86_REG_XMM9:
            return x86_const.X86_REG_ZMM9

        case (
            x86_const.X86_REG_ZMM10 | x86_const.X86_REG_YMM10 | x86_const.X86_REG_XMM10
        ):
            return x86_const.X86_REG_ZMM10

        case (
            x86_const.X86_REG_ZMM11 | x86_const.X86_REG_YMM11 | x86_const.X86_REG_XMM11
        ):
            return x86_const.X86_REG_ZMM11

        case (
            x86_const.X86_REG_ZMM12 | x86_const.X86_REG_YMM12 | x86_const.X86_REG_XMM12
        ):
            return x86_const.X86_REG_ZMM12

        case (
            x86_const.X86_REG_ZMM13 | x86_const.X86_REG_YMM13 | x86_const.X86_REG_XMM13
        ):
            return x86_const.X86_REG_ZMM13

        case (
            x86_const.X86_REG_ZMM14 | x86_const.X86_REG_YMM14 | x86_const.X86_REG_XMM14
        ):
            return x86_const.X86_REG_ZMM14

        case (
            x86_const.X86_REG_ZMM15 | x86_const.X86_REG_YMM15 | x86_const.X86_REG_XMM15
        ):
            return x86_const.X86_REG_ZMM15

        case (
            x86_const.X86_REG_ZMM16 | x86_const.X86_REG_YMM16 | x86_const.X86_REG_XMM16
        ):
            return x86_const.X86_REG_ZMM16

        case (
            x86_const.X86_REG_ZMM17 | x86_const.X86_REG_YMM17 | x86_const.X86_REG_XMM17
        ):
            return x86_const.X86_REG_ZMM17

        case (
            x86_const.X86_REG_ZMM18 | x86_const.X86_REG_YMM18 | x86_const.X86_REG_XMM18
        ):
            return x86_const.X86_REG_ZMM18

        case (
            x86_const.X86_REG_ZMM19 | x86_const.X86_REG_YMM19 | x86_const.X86_REG_XMM19
        ):
            return x86_const.X86_REG_ZMM19

        case (
            x86_const.X86_REG_ZMM20 | x86_const.X86_REG_YMM20 | x86_const.X86_REG_XMM20
        ):
            return x86_const.X86_REG_ZMM20

        case (
            x86_const.X86_REG_ZMM21 | x86_const.X86_REG_YMM21 | x86_const.X86_REG_XMM21
        ):
            return x86_const.X86_REG_ZMM21

        case (
            x86_const.X86_REG_ZMM22 | x86_const.X86_REG_YMM22 | x86_const.X86_REG_XMM22
        ):
            return x86_const.X86_REG_ZMM22

        case (
            x86_const.X86_REG_ZMM23 | x86_const.X86_REG_YMM23 | x86_const.X86_REG_XMM23
        ):
            return x86_const.X86_REG_ZMM23

        case (
            x86_const.X86_REG_ZMM24 | x86_const.X86_REG_YMM24 | x86_const.X86_REG_XMM24
        ):
            return x86_const.X86_REG_ZMM24

        case (
            x86_const.X86_REG_ZMM25 | x86_const.X86_REG_YMM25 | x86_const.X86_REG_XMM25
        ):
            return x86_const.X86_REG_ZMM25

        case (
            x86_const.X86_REG_ZMM26 | x86_const.X86_REG_YMM26 | x86_const.X86_REG_XMM26
        ):
            return x86_const.X86_REG_ZMM26

        case (
            x86_const.X86_REG_ZMM27 | x86_const.X86_REG_YMM27 | x86_const.X86_REG_XMM27
        ):
            return x86_const.X86_REG_ZMM27

        case (
            x86_const.X86_REG_ZMM28 | x86_const.X86_REG_YMM28 | x86_const.X86_REG_XMM28
        ):
            return x86_const.X86_REG_ZMM28

        case (
            x86_const.X86_REG_ZMM29 | x86_const.X86_REG_YMM29 | x86_const.X86_REG_XMM29
        ):
            return x86_const.X86_REG_ZMM29

        case (
            x86_const.X86_REG_ZMM30 | x86_const.X86_REG_YMM30 | x86_const.X86_REG_XMM30
        ):
            return x86_const.X86_REG_ZMM30

        case (
            x86_const.X86_REG_ZMM31 | x86_const.X86_REG_YMM31 | x86_const.X86_REG_XMM31
        ):
            return x86_const.X86_REG_ZMM31

        case x86_const.X86_REG_IP | x86_const.X86_REG_EIP | x86_const.X86_REG_RIP:
            return x86_const.X86_REG_RIP

        case x86_const.X86_REG_EFLAGS:
            return x86_const.X86_REG_EFLAGS

    print(
        f"Unsupported register {cs.reg_name(r)} in register_normalize", file=sys.stderr
    )
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
        case x86_const.X86_REG_ZMM0:
            return 16
        case x86_const.X86_REG_ZMM1:
            return 17
        case x86_const.X86_REG_ZMM2:
            return 18
        case x86_const.X86_REG_ZMM3:
            return 19
        case x86_const.X86_REG_ZMM4:
            return 20
        case x86_const.X86_REG_ZMM5:
            return 21
        case x86_const.X86_REG_ZMM6:
            return 22
        case x86_const.X86_REG_ZMM7:
            return 23
        case x86_const.X86_REG_ZMM8:
            return 24
        case x86_const.X86_REG_ZMM9:
            return 25
        case x86_const.X86_REG_ZMM10:
            return 26
        case x86_const.X86_REG_ZMM11:
            return 27
        case x86_const.X86_REG_ZMM12:
            return 28
        case x86_const.X86_REG_ZMM13:
            return 29
        case x86_const.X86_REG_ZMM14:
            return 30
        case x86_const.X86_REG_ZMM15:
            return 31
        case x86_const.X86_REG_ZMM16:
            return 32
        case x86_const.X86_REG_ZMM17:
            return 33
        case x86_const.X86_REG_ZMM18:
            return 34
        case x86_const.X86_REG_ZMM19:
            return 35
        case x86_const.X86_REG_ZMM20:
            return 36
        case x86_const.X86_REG_ZMM21:
            return 37
        case x86_const.X86_REG_ZMM22:
            return 38
        case x86_const.X86_REG_ZMM23:
            return 39
        case x86_const.X86_REG_ZMM24:
            return 40
        case x86_const.X86_REG_ZMM25:
            return 41
        case x86_const.X86_REG_ZMM26:
            return 42
        case x86_const.X86_REG_ZMM27:
            return 43
        case x86_const.X86_REG_ZMM28:
            return 44
        case x86_const.X86_REG_ZMM29:
            return 45
        case x86_const.X86_REG_ZMM30:
            return 46
        case x86_const.X86_REG_ZMM31:
            return 47

    print(f"Unsupported register {cs.reg_name(r)} in cs_to_taint_idx", file=sys.stderr)
    sys.exit(1)


def generate_cmov_instrumentation(
    line: bytes, insn: CsInsn, config: Config
) -> list[Instruction]:
    instructions: list[Instruction] = [
        Instruction(b"pushfq"),
        Instruction(b"push", Register(b"rax")),
        Instruction(b"push", Register(b"rbx")),
        Instruction(b"lea", Register(b"rbx"), get_memory_operand(line, insn, config)),
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
    return instructions


def generate_generic_memory_instrumentation(
    line: bytes, insn: CsInsn, config: Config
) -> list[Instruction]:
    instructions: list[Instruction] = [
        Instruction(b"pushfq"),
        Instruction(b"push", Register(b"rax")),
        Instruction(b"push", Register(b"rbx")),
        Instruction(
            b"lea",
            Register(b"rax"),
            get_memory_operand(line, insn, config),
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

    return instructions


def generate_reg_taint_check(
    line: bytes, insn: CsInsn, r: int, config: Config
) -> list[Instruction]:
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
                get_memory_operand(line, insn, config),
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
                    displacement=cs_to_taint_idx(register_normalize(r)),
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
                    displacement=cs_to_taint_idx(register_normalize(r)),
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

    return instructions


def generate_generic_reg_taint_update(r: int) -> list[Instruction]:
    instructions: list[Instruction] = [
        Instruction(b"push", Register(b"rax")),
        Instruction(
            b"lea",
            Register(b"rax"),
            EffectiveAddress(
                offset=Label(b"abisan_taint_state"),
                base=Register(b"rip"),
                displacement=cs_to_taint_idx(register_normalize(r)),
            ),
        ),
        Instruction(
            b"and",
            EffectiveAddress(width=EAWidth.BYTE_PTR, base=Register(b"rax")),
            Immediate(str(bitwise_neg8(get_taint_mask(r))).encode("ascii")),
        ),
        Instruction(b"pop", Register(b"rax")),
    ]

    return instructions


def generate_cmov_reg_taint_update(insn: CsInsn, r: int) -> list[Instruction]:
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
                displacement=cs_to_taint_idx(register_normalize(r)),
            ),
        ),
        Instruction(
            b"mov",
            Register(b"bl"),
            EffectiveAddress(width=EAWidth.BYTE_PTR, base=Register(b"rax")),
        ),
        Instruction(b"mov", Register(b"cl"), Register(b"bl")),
        Instruction(
            b"and",
            Register(b"cl"),
            Immediate(str(bitwise_neg8(get_taint_mask(r))).encode("ascii")),
        ),
        Instruction(insn.mnemonic.encode("ascii"), Register(b"rbx"), Register(b"rcx")),
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
    return instructions


def generate_taint_after_call() -> list[Instruction]:
    # Taint everything that could have been clobbered in a call

    instructions: list[Instruction] = [
        Instruction(b"push", Register(b"rdi")),
        Instruction(
            b"lea",
            Register(b"rdi"),
            EffectiveAddress(
                width=EAWidth.BYTE_PTR,
                base=Register(b"rip"),
                offset=Label(b"abisan_taint_state"),
            ),
        ),
        Instruction(
            b"mov",
            EffectiveAddress(
                width=EAWidth.BYTE_PTR,
                base=Register(b"rdi"),
                displacement=TAINT_STATE_RAX,
            ),
            Immediate(b"0"),
        ),
        Instruction(
            b"mov",
            EffectiveAddress(
                width=EAWidth.BYTE_PTR,
                base=Register(b"rdi"),
                displacement=TAINT_STATE_RCX,
            ),
            Immediate(b"0xff"),
        ),
        Instruction(
            b"mov",
            EffectiveAddress(
                width=EAWidth.BYTE_PTR,
                base=Register(b"rdi"),
                displacement=TAINT_STATE_RDX,
            ),
            Immediate(b"0xff"),
        ),
        Instruction(
            b"mov",
            EffectiveAddress(
                width=EAWidth.BYTE_PTR,
                base=Register(b"rdi"),
                displacement=TAINT_STATE_RDI,
            ),
            Immediate(b"0xff"),
        ),
        Instruction(
            b"mov",
            EffectiveAddress(
                width=EAWidth.BYTE_PTR,
                base=Register(b"rdi"),
                displacement=TAINT_STATE_RSI,
            ),
            Immediate(b"0xff"),
        ),
        Instruction(
            b"mov",
            EffectiveAddress(
                width=EAWidth.BYTE_PTR,
                base=Register(b"rdi"),
                displacement=TAINT_STATE_R8,
            ),
            Immediate(b"0xff"),
        ),
        Instruction(
            b"mov",
            EffectiveAddress(
                width=EAWidth.BYTE_PTR,
                base=Register(b"rdi"),
                displacement=TAINT_STATE_R9,
            ),
            Immediate(b"0xff"),
        ),
        Instruction(
            b"mov",
            EffectiveAddress(
                width=EAWidth.BYTE_PTR,
                base=Register(b"rdi"),
                displacement=TAINT_STATE_R10,
            ),
            Immediate(b"0xff"),
        ),
        Instruction(
            b"mov",
            EffectiveAddress(
                width=EAWidth.BYTE_PTR,
                base=Register(b"rdi"),
                displacement=TAINT_STATE_R11,
            ),
            Immediate(b"0xff"),
        ),
        Instruction(b"pop", Register(b"rdi")),
    ]

    return instructions


def main() -> None:
    if len(sys.argv) != 2:
        print(
            f"Usage: python3 {sys.argv[0]} <assembly_file>",
            file=sys.stderr,
        )
        sys.exit(1)

    tunables: list[str] = [
        os.environ.get(REDZONE_ENABLED_ENV_NAME, ""),
        os.environ.get(STACK_SIZE_ENV_NAME, ""),
        os.environ.get(SYNTAX_ENV_NAME, ""),
    ]
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

            # Remove unnecessary additions by non gcc compilers
            if not any(x in line for x in AS_UNSUPPORTED):
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
                            serialize(
                                generate_cmov_instrumentation(line, insn, config),
                                config,
                            )
                        )
                    else:
                        f.write(
                            serialize(
                                generate_generic_memory_instrumentation(
                                    line, insn, config
                                ),
                                config,
                            )
                        )

                if needs_taint_check_for_read(insn):
                    for r in get_registers_read(insn):
                        f.write(
                            serialize(
                                generate_reg_taint_check(line, insn, r, config), config
                            )
                        )

                if needs_taint_update_for_write(insn):
                    for r in get_registers_written(insn):
                        if insn.mnemonic.startswith("cmov"):
                            f.write(
                                serialize(
                                    generate_cmov_reg_taint_update(insn, r), config
                                )
                            )
                        else:
                            f.write(
                                serialize(generate_generic_reg_taint_update(r), config)
                            )

            if not any(x in line for x in AS_UNSUPPORTED):
                f.write(line + b"\n")

            if insn is not None and insn.mnemonic.startswith("call"):
                f.write(serialize(generate_taint_after_call(), config))

            if get_label_name(line) in global_symbols:
                f.write(b"    call abisan_function_entry\n")


if __name__ == "__main__":
    main()

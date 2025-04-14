from dataclasses import dataclass
from enum import Enum

from typing import Optional

import capstone  # type: ignore
from capstone import Cs, x86_const

cs: Cs = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True

# Serialize Instruction instances into Intel or AT&T syntax
# Assumes that caller will order operands for Instruction.operands in destination, source order
# Ex.
# Instruction(b"mov",[Register(b"r11"),Immediate(b"0x10")]).serialize_intel() == "     mov r11, 0x10"
# Instruction(b"mov",[Register(b"r11"),Immediate(b"0x10")]).serialize_att() ==   "     mov $0x10, %r11"


@dataclass
class Register:
    val: bytes


@dataclass
class Immediate:
    val: bytes


@dataclass
class Label:
    val: bytes


class EAWidth(Enum):
    BYTE_PTR = 0
    WORD_PTR = 1
    DWORD_PTR = 2
    QWORD_PTR = 3
    XMMWORD_PTR = 4
    YMMWORD_PTR = 5
    ZMMWORD_PTR = 6

    def serialize_intel(self) -> bytes:
        if self.name == "BYTE_PTR":
            return b"byte ptr"
        if self.name == "WORD_PTR":
            return b"word ptr"
        if self.name == "DWORD_PTR":
            return b"dword ptr"
        if self.name == "QWORD_PTR":
            return b"qword ptr"
        if self.name == "XMMWORD_PTR":
            return b"xmmword ptr"
        if self.name == "YMMWORD_PTR":
            return b"ymmword ptr"
        if self.name == "ZMMWORD_PTR":
            return b"zmmword ptr"
        raise ValueError("This should never happen")

    def serialize_att(self) -> bytes:
        if self.name == "BYTE_PTR":
            return b"b"
        if self.name == "WORD_PTR":
            return b"w"
        if self.name == "DWORD_PTR":
            return b"d"
        if self.name == "QWORD_PTR":
            return b"q"
        if self.name == "XMMWORD_PTR":
            return b"x"
        if self.name == "YMMWORD_PTR":
            return b"y"
        if self.name == "ZMMWORD_PTR":
            return b"z"
        raise ValueError("This should never happen")


@dataclass
class EffectiveAddress:
    width: Optional[EAWidth] = None
    base: Optional[Register] = None
    index: Optional[Register] = None
    scale: Optional[Immediate] = None
    displacement: Optional[Immediate] = None
    offset: Optional[Label] = None


@dataclass
class JumpTarget:
    target: EffectiveAddress | Label | Register | Immediate


def handle_EA_att(op: EffectiveAddress, isJumpTarget: bool) -> tuple[bytes, bytes]:
    instr: bytes = b"*" if isJumpTarget else b""

    if op.displacement is not None:
        instr += op.displacement.val

        if isinstance(op.offset, Label):
            instr += b"+" + op.offset.val

        instr += b"("
        needs_comma = False
        for component in [op.base, op.index, op.scale]:
            if component is not None:
                if needs_comma:
                    instr += b", "
                instr += (
                    b"%" + component.val
                    if isinstance(component, Register)
                    else component.val
                )
                needs_comma = True
        instr += b")"
    return (op.width.serialize_att() if op.width is not None else b"", instr)


def handle_EA_intel(op: EffectiveAddress) -> bytes:
    instr: bytes = b""
    if op.width is not None:
        instr += op.width.serialize_intel()

    if isinstance(op.offset, Label):
        instr += b"offset " + op.offset.val

    instr += b" ["
    needs_plus = False

    if op.base is not None:
        instr += op.base.val

        needs_plus = True

    if op.scale is not None and op.index is not None:
        if needs_plus:
            instr += b" + "

        instr += op.index.val + b" * " + op.scale.val

        needs_plus = True

    if op.displacement is not None:
        if needs_plus:
            instr += b" + "

        instr += op.displacement.val

    instr += b"]"
    return instr


@dataclass
class Instruction:
    mnemonic: bytes
    operands: list[
        Register | Immediate | Label | EffectiveAddress
    ]  # registers and immediates are passed as byte strings

    # displacement(base,index,scale)
    # immediates (not scale) get $ in front of them, addresses do not
    # registers get % in front of them
    # mov source, destination
    def serialize_att(self) -> bytes:
        instr = b""
        mnem = b"     " + self.mnemonic + b" "

        for i in range(len(self.operands), 0, -1):  # Loop starting at last element

            # Assumes operands are provided in destination, source order
            op = self.operands[i - 1]

            if isinstance(op, Register):
                instr += b"%" + op.val
            elif isinstance(op, Immediate):
                instr += b"$" + op.val
            elif isinstance(op, Label):
                instr += op.val

            elif isinstance(op, JumpTarget):
                if isinstance(op.target, Immediate) or isinstance(op.target, Label):
                    instr += op.target.val
                if isinstance(op.target, Register):
                    instr += b"*%" + op.target.val
                if isinstance(op.target, EffectiveAddress):
                    instr += handle_EA_att(op.target, isJumpTarget=True)[1]

            else:  # is EffectiveAddress
                EA = handle_EA_att(op, isJumpTarget=False)
                instr += EA[1]
                mnem = b"     " + self.mnemonic + EA[0] + b" "

            if i > 1:
                instr += b", "

        return mnem + instr

    def serialize_intel(self) -> bytes:
        instr = b"     " + self.mnemonic + b" "

        for i in range(len(self.operands)):
            op = self.operands[i]

            if isinstance(op, JumpTarget):
                if isinstance(op.target, EffectiveAddress):
                    instr += handle_EA_intel(op.target)
                else:
                    instr += op.target.val

            elif isinstance(op, EffectiveAddress):
                instr += handle_EA_intel(op)
            else:  # Is register or immediate
                instr += op.val

            if i < len(self.operands) - 1:
                instr += b", "

        return instr

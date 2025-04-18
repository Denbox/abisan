from dataclasses import dataclass
from enum import Enum
from typing import TypeGuard
import re

# Serialize Instruction instances into Intel or AT&T syntax
# Assumes that caller will order operands for Instruction.operands in destination, source order
# Ex.
# Instruction(b"mov",[Register(b"r11"),Immediate(b"0x10")]).serialize_intel() == "     mov r11, 0x10"
# Instruction(b"mov",[Register(b"r11"),Immediate(b"0x10")]).serialize_att() ==   "     mov $0x10, %r11"


def is_decimal(num: bytes) -> bool:
    return num.isdigit()


def is_hexadecimal(num: bytes) -> bool:
    if num.startswith(b"0x") or num.startswith(b"0X"):
        num = num[2:]
    return all(c in b"0123456789abcedfABCDEF" for c in num)


@dataclass
class Register:
    val: bytes

    def serialize_att(self) -> bytes:
        return b"%" + self.val

    def serialize_intel(self) -> bytes:
        return self.val


@dataclass
class Immediate:
    val: bytes

    def serialize_att(self) -> bytes:
        return b"$" + self.val

    def serialize_intel(self) -> bytes:
        return self.val


@dataclass
class Label:
    val: bytes

    def serialize_intel(self) -> bytes:
        return self.val

    def serialize_att(self) -> bytes:
        return self.val


class EAWidth(Enum):
    BYTE_PTR = 0
    WORD_PTR = 1
    DWORD_PTR = 2
    QWORD_PTR = 3
    XMMWORD_PTR = 4
    YMMWORD_PTR = 5
    ZMMWORD_PTR = 6

    def serialize_intel(self) -> bytes:
        return self.name.lower().replace("_", " ").encode("ascii")

    def serialize_att(self) -> bytes:
        # TODO: handle movl as dword
        return self.name[0].lower().encode("ascii")

    @staticmethod
    def deserialize_intel(width: bytes) -> "EAWidth":
        key: str = width.decode("ascii").upper().replace(" ", "_")

        return EAWidth[key]

    @staticmethod
    def deserialize_att(width: bytes) -> "EAWidth":
        # TODO: handle movl as dword
        # TODO: This dict sucks
        # Could just make it return directly what it gets from the dict
        widths: dict[bytes, str] = {
            b"b": "BYTE_PTR",
            b"w": "WORD_PTR",
            b"d": "DWORD_PTR",
            b"l": "DWORD_PTR",
            b"q": "QWORD_PTR",
            b"x": "XMMWORD_PTR",
            b"y": "YMMWORD_PTR",
            b"z": "ZMMWORD_PTR",
        }

        return EAWidth[widths[width[0:1].lower()]]


@dataclass
class EffectiveAddress:
    width: EAWidth | None = None
    base: Register | None = None
    index: Register | None = None
    scale: int | None = None
    displacement: Immediate | None = None
    offset: Label | None = None

    def serialize_intel(self) -> bytes:
        result: bytes = b""
        if self.width is not None:
            result += self.width.serialize_intel() + b" "
        if self.offset is not None:
            result += b"offset " + self.offset.serialize_intel()
        result += b" ["
        ea_components: list[bytes] = []
        if self.base is not None:
            ea_components.append(self.base.serialize_intel())
        if self.index is not None and self.scale is not None:
            ea_components.append(
                self.index.serialize_intel() + b"*" + str(self.scale).encode("ascii")
            )
        if self.displacement is not None:
            ea_components.append(self.displacement.serialize_intel())
        result += b"+".join(ea_components)
        result += b"]"
        return result

    def serialize_att(self) -> bytes:
        result: bytes = b""
        if self.displacement is not None:
            result += self.displacement.serialize_att()
        if self.offset is not None:
            result += b"+" + self.offset.serialize_att()
        ea_components: list[bytes] = []
        if self.base is not None:
            ea_components.append(self.base.serialize_att())
        if self.index is not None:
            ea_components.append(self.index.serialize_att())
        if self.scale is not None:
            ea_components.append(str(self.scale).encode("ascii"))
        result += b",".join(ea_components)
        result += b")"
        return result

    @staticmethod
    def deserialize_intel(memory_operand: bytes) -> "EffectiveAddress":
        # Expects memory operand in format width [base+index*scale+displacement]
        # With all parts being optional, may or may not have spaces around each

        # TODO: Rename one of the 2 things we called 'offset'
        ea_match: re.Match[bytes] | None = re.match(
            rb"(?P<width>[^\[]*)\[(?P<offset>[^\]]*)\]", memory_operand
        )
        assert ea_match is not None

        # Could be width or could be "offset label"
        # TODO: Handle rip relative movs like: offset label[rip + immediate]
        width_key: bytes = ea_match["width"].strip(b" \t")

        width: EAWidth | None = EAWidth.deserialize_intel(width_key) if len(width_key) > 0 else None

        offset: bytes = b"".join(ea_match["offset"].strip(b" \t").split())

        # combinations:
        # [base]
        # [displacement]
        # [base+displacement]
        # [index*scale+displacement]
        # [base+index+displacement]
        # [base+index*scale+displacement]
        terms: list[bytes] = offset.split(b"+")

        # If both index and scale are present, set them
        scale: int | None = None
        index: Register | None = None
        for term in terms:
            if b"*" in term:
                idx, scl = term.split(b"*")
                index = Register(idx)
                if is_hexadecimal(scl):
                    scale = int(scl, 16)
                else:
                    raise ValueError("Invalid scale")

        # Case of having index, but no scale
        if index is None and scale is None and len(terms) >= 3:
            index = Register(terms[1])

        # If there are multiple terms and (scale is not present, or there are 3 terms)
        base: Register | None = None
        if len(terms) > 1 and (scale is None or len(terms) == 3):
            base = Register(terms[0])

        # If displacement exists, it is always the last term
        displacement: Immediate | None = None
        if len(terms) > 1 or (is_hexadecimal(terms[0]) or is_decimal(terms[0])):
            displacement = Immediate(terms[-1])
        else:
            # If displacement does not exist, base is the first term
            base = Register(terms[0])

        return EffectiveAddress(
            width=width, base=base, index=index, scale=scale, displacement=displacement
        )

    @staticmethod
    def deserialize_att(memory_operand: bytes) -> "EffectiveAddress":
        return EffectiveAddress() #TODO


@dataclass
class JumpTarget:
    val: EffectiveAddress | Label | Register | Immediate

    def serialize_att(self) -> bytes:
        if isinstance(self.val, (Register, EffectiveAddress)):
            return b"*" + self.val.serialize_att()
        if isinstance(self.val, (Label, Immediate)):
            return self.val.serialize_att()
        raise ValueError("This should never happen!")

    def serialize_intel(self) -> bytes:
        return self.val.serialize_intel()


def is_valid_operand_list(
    operands: list[object],
) -> TypeGuard[list[Register | Immediate | Label | EffectiveAddress | JumpTarget]]:
    return all(isinstance(op, (Register, Immediate, Label, EffectiveAddress, JumpTarget)) for op in operands)


@dataclass
class Instruction:
    mnemonic: bytes
    operands: list[Register | Immediate | Label | EffectiveAddress | JumpTarget]

    def __init__(self, mnemonic: bytes, *operands: object):
        operand_list = list(operands)
        if not is_valid_operand_list(operand_list):
            raise ValueError("Invalid operand list!")
        self.mnemonic = mnemonic
        self.operands = operand_list

    def serialize_att(self) -> bytes:
        mnemonic: bytes = self.mnemonic
        for op in self.operands:
            if isinstance(op, EffectiveAddress) and op.width is not None:
                # If an instruction has 2 EA operands, this will be intentionally wrong, and shouldn't assemble.
                mnemonic += op.width.serialize_att()
        return (
            b"    "
            + mnemonic
            + b" "
            + b", ".join(op.serialize_att() for op in reversed(self.operands))
        )

    def serialize_intel(self) -> bytes:
        return (
            b"    "
            + self.mnemonic
            + b" "
            + b", ".join(op.serialize_intel() for op in self.operands)
        )

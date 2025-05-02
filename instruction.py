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
    return re.match(rb"\A[-+]?(?:0[xX])?[0-9a-fA-F]+\Z", num) is not None


def is_register_att(reg: bytes) -> bool:
    return re.match(rb"\A%[0-9a-zA-Z]+\Z", reg) is not None


# bitwise negation of 64bit int
def bitwise_neg64(i: int) -> int:
    return int("".join("1" if bit == "0" else "0" for bit in bin(i)[2:].zfill(64)), 2)


def to_signed_64(num_str: bytes) -> bytes:
    if num_str.startswith(b"-"):

        base: int | None = (
            10
            if is_decimal(num_str[1:])
            else 16 if is_hexadecimal(num_str[1:]) else None
        )
        if base is None:
            raise ValueError(
                "Bytes Number "
                + num_str[1:].decode("ascii")
                + " passed to to_signed_64 is not base 10 or 16"
            )

        num: int = bitwise_neg64(int(num_str[1:], base)) + 1
        return hex(num).encode("ascii")

    else:
        if num_str.startswith(b"+"):
            return num_str[1:]
        return num_str


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
    displacement: int | Label | None = None  # TODO: displacement can be a label
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
            if isinstance(self.displacement, int):
                ea_components.append(hex(self.displacement).encode("ascii"))
            elif isinstance(self.displacement, Label):
                ea_components.append(self.displacement.serialize_intel())
            else:
                assert False
        result += b"+".join(ea_components)
        result += b"]"
        return result

    def serialize_att(self) -> bytes:
        result: bytes = b""
        if self.displacement is not None:
            if isinstance(self.displacement, int):
                result += hex(self.displacement).encode("ascii")
            elif isinstance(self.displacement, Label):
                result += self.displacement.serialize_att()
            else:
                assert False
        if self.offset is not None:
            if self.displacement is not None:
                result += b"+"
            result += self.offset.serialize_att()
        ea_components: list[bytes] = []
        if self.base is not None:
            ea_components.append(self.base.serialize_att())
        if self.index is not None:
            ea_components.append(self.index.serialize_att())
        if self.scale is not None:
            ea_components.append(str(self.scale).encode("ascii"))
        result += b"("
        result += b",".join(ea_components)
        result += b")"
        return result

    @staticmethod
    def deserialize_intel(
        mem_prefix: bytes, memory_operand: bytes
    ) -> "EffectiveAddress | None":
        # TODO: support gcc effective address format, currently only supports clang
        # Expects memory operand in format width [base+index*scale+displacement]
        # mem_prefix could be width or could be "offset label"

        # Reformatting memory operand:
        # Moving displacement to end if necessary
        # Remove []
        mem_op_reformatted: bytes = memory_operand
        operand_parts: list[bytes] = b"".join(memory_operand.split()).split(b"[")
        if len(operand_parts) >= 2 and len(operand_parts[0]) > 0:

            # TODO: handle single-quoted []
            assert len(operand_parts) == 2

            if is_hexadecimal(operand_parts[0][1:]):
                operand_parts[0] = to_signed_64(operand_parts[0])

            # Displacement is on the left
            mem_op_reformatted = b"+".join(operand_parts[::-1])

        mem_op_reformatted = mem_op_reformatted.replace(b"[", b"").replace(b"]", b"")

        offset: Label | None = None
        width: EAWidth | None = None
        if b"offset" in mem_prefix:
            offset = Label((mem_prefix.split()[1]).strip(b" \t"))
        else:
            width = (
                EAWidth.deserialize_intel(mem_prefix.strip(b" \t"))
                if len(mem_prefix.strip(b" \t")) > 0
                else None
            )

        # combinations:
        # [base]
        # [displacement]
        # [base+displacement] or displacement[base]
        # [index*scale+displacement] or displacement[index*scale]
        # [base+index+displacement] or displacement[base+index]
        # [base+index*scale+displacement] or displacement[base+index*scale]
        # [base+index*scale] HANDLE

        # TODO: Displacement can be a label
        # If displacement is a label, assume that it will always be added
        terms: list[bytes] = mem_op_reformatted.split(b"+")

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
        displacement: int | Label | None = None
        if len(terms) > 1 or is_hexadecimal(terms[0]):
            if is_hexadecimal(terms[-1]):
                displacement = int(terms[-1], 16)
            else:
                displacement = Label(terms[-1])
        else:
            # If displacement does not exist, base is the first term
            base = Register(terms[0])

        return EffectiveAddress(
            width=width,
            base=base,
            index=index,
            scale=scale,
            displacement=displacement,
            offset=offset,
        )

    @staticmethod
    def deserialize_att(
        width_string: bytes, memory_operand: bytes
    ) -> "EffectiveAddress | None":

        width: EAWidth | None = None
        # No width
        if len(width_string) > 0:
            width = EAWidth.deserialize_att(width_string)

        # Displacement may have to be an int
        displacement: int | None = None
        base: Register | None = None
        index: Register | None = None
        scale: int | None = None

        # Combinations of components:
        # (%base)
        # displacement
        # displacement(%base)
        # displacement(%base,%index)
        # displacement(%base,%index,scale)
        # displacement(%index,scale)
        # (%base,%index,scale)

        # Remove trailing operands
        rightmost_comma_index: int
        rightmost_close_parenthesis_index: int
        memory_op_clean: bytes = b"".join(
            memory_operand.split(b" ")  # How to also split on tabs?
        )
        while (rightmost_comma_index := memory_op_clean.rfind(b",")) > (
            rightmost_close_parenthesis_index := memory_op_clean.rfind(b")")
        ):
            memory_op_clean = memory_op_clean[:rightmost_comma_index]

        # TODO: displacement can be a label
        match memory_op_clean.split(b","):
            # Cases may contain non-memory operands before the memory operand
            # In att, it is generally not permitted to have more than one memory operand in a single instruction

            case [t1, t2, t3]:
                # Contains:
                # (%base,%index,scale)
                # displacement(%base,%index,scale)

                if not b"(" in t1:
                    return None

                disp, t1 = t1.split(b"(")

                # Displacement must be able to be a hexadecimal
                # Base is a register
                if (len(disp) > 0 and not is_hexadecimal(disp)) or not is_register_att(
                    t1
                ):
                    return None

                displacement = int(disp, 16) if len(disp) > 0 else None

                base = Register(t1)

                t3 = t3.strip(b")")
                # Index is a register
                # Scale is not an immediate; should be represented as hexadecimal
                if not is_register_att(t2) or not is_hexadecimal(t3):
                    return None

                index = Register(t2)
                scale = int(t3, 16)

            case [t1, t2]:
                # Contains:
                # displacement(%base,%index)
                # displacement(%index,scale)

                if not b"(" in t1:
                    return None

                # Separate Displacement from the base/index:
                disp, t1 = t1.split(b"(")
                t2 = t2.strip(b")")

                # Displacement must be able to be a hexadecimal (not immediate)
                # Base/Index is a register
                if (len(disp) > 0 and not is_hexadecimal(disp)) or not is_register_att(
                    t1
                ):
                    return None

                displacement = int(disp, 16) if len(disp) > 0 else None

                if is_register_att(t2):  # displacement(%base, %index)
                    base = Register(t1)
                    index = Register(t2)
                elif is_hexadecimal(t2):  # displacement(%index, scale)
                    index = Register(t1)
                    scale = int(t2, 16)
                else:
                    return None

            case [t1]:
                # Contains:
                # (%base)
                # displacement
                # displacement(%base)
                # offset(%base = %rip)

                disp_or_offset: bytes = b""
                if b"(" in t1:
                    disp_or_offset, t1 = t1.split(b"(")
                    t1 = t1.strip(b")")

                    if not is_register_att(t1):
                        return None
                    base = Register(t1)
                else:
                    disp_or_offset = t1

                # displacment or offset will never be a register or immediate
                if len(disp_or_offset) > 0 and (
                    is_register_att(disp_or_offset) or disp_or_offset.startswith(b"$")
                ):
                    return None

                if len(disp_or_offset) > 0:
                    if is_hexadecimal(disp_or_offset) and len(disp_or_offset):
                        displacement = int(disp_or_offset, 16)
                    else:
                        offset = Label(disp_or_offset)
                else:
                    displacement = None

            case _:
                return None

        # Registers will have leading "%", which we must strip
        if base is not None:
            base.val = base.val.strip(b"%")
        if index is not None:
            index.val = index.val.strip(b"%")

        return EffectiveAddress(
            width=width, displacement=displacement, base=base, index=index, scale=scale
        )


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
    return all(
        isinstance(op, (Register, Immediate, Label, EffectiveAddress, JumpTarget))
        for op in operands
    )


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
            if (
                isinstance(op, EffectiveAddress)
                and op.width is not None
                and not b"lea" in mnemonic
            ):
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

from dataclasses import dataclass
from enum import Enum
from typing import TypeGuard
import re
import asm_re

# Serialize Instruction instances into Intel or AT&T syntax
# Assumes that caller will order operands for Instruction.operands in destination, source order
# Ex.
# Instruction(b"mov",Register(b"r11"),Immediate(b"0x10")).serialize_intel() == "     mov r11, 0x10"
# Instruction(b"mov",Register(b"r11"),Immediate(b"0x10")).serialize_att() ==   "     mov $0x10, %r11"


def is_decimal(num: bytes) -> bool:
    return num.isdigit()


def is_hexadecimal(num: bytes) -> bool:
    return re.match(rb"\A[-+]?(?:0[xX])[0-9a-fA-F]+\Z", num) is not None


def is_number(num: bytes) -> bool:
    return is_decimal(num) or is_hexadecimal(num)


def parse_number(num: bytes) -> int:
    if is_decimal(num):
        return int(num, 10)
    if is_hexadecimal(num):
        return int(num, 16)
    assert False


def is_register_att(reg: bytes) -> bool:
    return re.match(rb"\A%[0-9a-zA-Z]+\Z", reg) is not None


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
class Constant:
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
        # movl and movd are dword ptr
        char: str = (
            width[0:1].upper().decode("ascii")
            if not width.upper().startswith(b"L")
            else "D"
        )

        return EAWidth[
            next(
                (size for size in list(EAWidth.__members__) if size.startswith(char)),
                "",
            )
        ]


@dataclass
class EffectiveAddress:
    width: EAWidth | None = None
    base: Register | None = None
    index: Register | None = None
    scale: int | None = None
    displacement: Constant | None = None
    offset: Constant | None = None

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
        if len(ea_components) > 0:
            result += b"("
            result += b",".join(ea_components)
            result += b")"
        return result

    @staticmethod
    def deserialize_intel(
        unparsed_width: bytes | None, components: re.Match[bytes], operand_index: int
    ) -> "EffectiveAddress | None":

        if components[f"operand_{operand_index}"] is None:
            raise ValueError(f"Operand {operand_index} not found in match object")

        components_dict: dict[str, bytes | None] = components.groupdict()
        found_component_keys: list[str] = list(
            {k: v for k, v in components_dict.items() if v is not None}.keys()
        )
        permutation_num = next(
            (
                i
                for i in range(len(asm_re.intel_permute_ea()))
                if any(f"permutation_{i}" in key for key in found_component_keys)
            ),
            -1,
        )
        if permutation_num < 0:
            raise ValueError("No matching permutations found for intel memory operand")

        width: EAWidth | None = None
        if unparsed_width is not None:
            width = EAWidth.deserialize_intel(unparsed_width)

        unparsed_base: bytes | None = components_dict.get(
            f"operand_{operand_index}_permutation_{permutation_num}_base"
        )
        base: Register | None = (
            Register(unparsed_base) if unparsed_base is not None else None
        )

        unparsed_index: bytes | None = components_dict.get(
            f"operand_{operand_index}_permutation_{permutation_num}_index"
        )
        index: Register | None = (
            Register(unparsed_index) if unparsed_index is not None else None
        )

        unparsed_scale: bytes | None = components_dict.get(
            f"operand_{operand_index}_permutation_{permutation_num}_scale"
        )
        scale: int | None = (
            parse_number(unparsed_scale) if unparsed_scale is not None else None
        )

        unparsed_mem_op_sequence: bytes | None = components[
            f"operand_{operand_index}_mem_op_sequence"
        ]

        offset: Constant | None = None
        if (
            unparsed_mem_op_sequence is not None
            and b"offset" in unparsed_mem_op_sequence
        ):
            # XXX: Assumes non-zero displacement in rip-relative moves
            offset = Constant(
                components[
                    f"operand_{operand_index}_permutation_{permutation_num}_displacement"
                ]
            )

        displacement: Constant | None = None
        if offset is None:
            unparsed_displacement: bytes | None = components_dict.get(
                f"operand_{operand_index}_permutation_{permutation_num}_displacement"
            )
            if unparsed_displacement is not None:
                displacement = Constant(unparsed_displacement)

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
        unparsed_width: bytes | None, components: re.Match[bytes], operand_index: int
    ) -> "EffectiveAddress | None":

        if components[f"operand_{operand_index}"] is None:
            raise ValueError(f"Operand {operand_index} not found in match object")

        width: EAWidth | None = None
        if unparsed_width is not None:
            width = EAWidth.deserialize_att(unparsed_width)

        unparsed_base: bytes | None = components[f"operand_{operand_index}_base"]
        base: Register | None = (
            Register(unparsed_base) if unparsed_base is not None else None
        )

        unparsed_index: bytes | None = components[f"operand_{operand_index}_index"]
        index: Register | None = (
            Register(unparsed_index) if unparsed_index is not None else None
        )

        unparsed_scale: bytes | None = components[f"operand_{operand_index}_scale"]
        scale: int | None = (
            parse_number(unparsed_scale) if unparsed_scale is not None else None
        )

        displacement: Constant | None = None
        unparsed_displacement: bytes | None = components[
            f"operand_{operand_index}_displacement"
        ]
        if unparsed_displacement is not None:
            displacement = Constant(unparsed_displacement)

        if base is not None:
            base.val = base.val.strip(b"%")
        if index is not None:
            index.val = index.val.strip(b"%")

        return EffectiveAddress(
            width=width,
            base=base,
            index=index,
            scale=scale,
            displacement=displacement,
            offset=None,
        )


@dataclass
class JumpTarget:
    val: EffectiveAddress | Constant | Register | Immediate

    def serialize_att(self) -> bytes:
        if isinstance(self.val, (Register, EffectiveAddress)):
            return b"*" + self.val.serialize_att()
        if isinstance(self.val, (Constant, Immediate)):
            return self.val.serialize_att()
        raise ValueError("This should never happen!")

    def serialize_intel(self) -> bytes:
        return self.val.serialize_intel()


def is_valid_operand_list(
    operands: list[object],
) -> TypeGuard[list[Register | Immediate | Constant | EffectiveAddress | JumpTarget]]:
    return all(
        isinstance(op, (Register, Immediate, Constant, EffectiveAddress, JumpTarget))
        for op in operands
    )


@dataclass
class Instruction:
    mnemonic: bytes
    operands: list[Register | Immediate | Constant | EffectiveAddress | JumpTarget]

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
                and b"lea" not in mnemonic
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

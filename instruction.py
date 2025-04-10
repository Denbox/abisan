from dataclasses import dataclass
from enum import Enum

import capstone  # type: ignore
from capstone import Cs, x86_const

cs: Cs = Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
cs.detail = True
    
@dataclass
class Register:
    reg: bytes

@dataclass
class Immediate:
    imm: bytes

class EAWidth(Enum):
    BYTE_PTR = 0
    WORD_PTR = 1
    DWORD_PTR = 2
    QWORD_PTR = 3
    XMMWORD_PTR = 4
    YMMWORD_PTR = 5
    ZMMWORD_PTR = 6

INTEL_WIDTH_STR : dict[EAWidth,bytes] = {
    EAWidth.BYTE_PTR : b"byte ptr",
    EAWidth.WORD_PTR : b"word ptr",
    EAWidth.DWORD_PTR : b"dword ptr",
    EAWidth.QWORD_PTR : b"qword ptr",
    EAWidth.XMMWORD_PTR : b"xmmword ptr",
    EAWidth.YMMWORD_PTR : b"ymmword ptr",
    EAWidth.ZMMWORD_PTR : b"zmmword ptr"
}


@dataclass
class EffectiveAddress:
    width: EAWidth | None
    base: Register | None
    index: Register | None
    scale: Immediate | None
    displacement: Immediate | None

@dataclass
class Instruction:
    mnemonic: bytes
    operands: list[Register | Immediate | EffectiveAddress] # registers and immediates are passed as byte strings

    def serialize_intel(self) -> bytes:
        instr = b"     " + self.mnemonic + b" "

        while len(self.operands) > 0:
            op = self.operands.pop(0)

            if isinstance(op,Register):
                instr += op.reg
            elif isinstance(op,Immediate):
                instr += op.imm
            else: # Is EffectiveAddress
                if op.width is not None:
                    instr += INTEL_WIDTH_STR[op.width]
                
                instr += b" ["
                needs_plus = False
                
            
                if op.base is not None:
                    instr += op.base.reg
                    
                    needs_plus = True
            
                if op.scale is not None and op.index is not None:
                    if needs_plus:
                        instr += b" + "
               

                    instr += op.index.reg + b" * " + op.scale.imm
                    
                    needs_plus = True
                   
                if op.displacement is not None:
                    if needs_plus:
                        instr += b" + "
                                            
                    instr += op.displacement.imm
                   
                instr += b"]"

            if len(self.operands) > 0:
                instr += b", "

        return instr
    def serialize_att(self) -> bytes:
        return b""

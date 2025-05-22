_OPERATOR: str = r"(?:[-+*/^&<>%|!]|<<|>>)"

_LABEL: str = r"(?:[a-z._][a-z0-9.@_]*)"

_MNEMONIC: str = r"(?P<mnemonic>[a-z][a-z0-9]+)"

# GNU as actually accepts `0x` on its own, but we won't support that
_HEX_NUMBER: str = r"(?:(?:[-+~][ \t]*)*0x[0-9a-f]+)"
_DEC_NUMBER: str = r"(?:(?:[-+~][ \t]*)*[0-9]+)"
_BIN_NUMBER: str = r"(?:(?:[-+~][ \t]*)*0b[01]+)"

_CHAR_CONSTANT: str = r"(?:(?:[-+~][ \t]*)*'.'|'\\.')"

_IMMEDIATE: str = rf"(?:\$?(?:{_HEX_NUMBER}|{_DEC_NUMBER}|{_BIN_NUMBER}|{_CHAR_CONSTANT}))"

_CONSTANT: str = rf"(?:{_LABEL}|{_IMMEDIATE})"

_CONSTANT_EXPRESSION: str = rf"(?:(?:{_CONSTANT}(?:[ \t]*{_OPERATOR}[ \t]*{_CONSTANT})*)?)"

_INTEL_DISPLACEMENT: str = rf"(?P<OP_NUM_PLACEHOLDER_PERMUTATION_PLACEHOLDER_displacement>{_CONSTANT_EXPRESSION})"

# Directly lifted from capstone
# https://github.com/capstone-engine/capstone/blob/42fbce6c524a3a57748f9de2b5460a7135e236c1/bindings/python/capstone/x86_const.py#L222
SEGMENT_REGISTERS: tuple[str, ...] = (
    'ss',
    'fs',
    'gs',
    'es',
    'cs',
    'ds',
)

REGISTERS: tuple[str, ...] = ('ah', 'al', 'ax', 'bh', 'bl', 'bp', 'bpl', 'bx', 'ch', 'cl', 'cx', 'dh', 'di', 'dil', 'dl', 'dx', 'eax', 'ebp', 'ebx', 'ecx', 'edi', 'edx', 'eflags', 'eip', 'eiz', 'esi', 'esp', 'fpsw', 'ip', 'rax', 'rbp', 'rbx', 'rcx', 'rdi', 'rdx', 'rip', 'riz', 'rsi', 'rsp', 'si', 'sil', 'sp', 'spl', 'cr0', 'cr1', 'cr2', 'cr3', 'cr4', 'cr5', 'cr6', 'cr7', 'cr8', 'cr9', 'cr10', 'cr11', 'cr12', 'cr13', 'cr14', 'cr15', 'dr0', 'dr1', 'dr2', 'dr3', 'dr4', 'dr5', 'dr6', 'dr7', 'dr8', 'dr9', 'dr10', 'dr11', 'dr12', 'dr13', 'dr14', 'dr15', 'fp0', 'fp1', 'fp2', 'fp3', 'fp4', 'fp5', 'fp6', 'fp7', 'k0', 'k1', 'k2', 'k3', 'k4', 'k5', 'k6', 'k7', 'mm0', 'mm1', 'mm2', 'mm3', 'mm4', 'mm5', 'mm6', 'mm7', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'st0', 'st1', 'st2', 'st3', 'st4', 'st5', 'st6', 'st7', 'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7', 'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15', 'xmm16', 'xmm17', 'xmm18', 'xmm19', 'xmm20', 'xmm21', 'xmm22', 'xmm23', 'xmm24', 'xmm25', 'xmm26', 'xmm27', 'xmm28', 'xmm29', 'xmm30', 'xmm31', 'ymm0', 'ymm1', 'ymm2', 'ymm3', 'ymm4', 'ymm5', 'ymm6', 'ymm7', 'ymm8', 'ymm9', 'ymm10', 'ymm11', 'ymm12', 'ymm13', 'ymm14', 'ymm15', 'ymm16', 'ymm17', 'ymm18', 'ymm19', 'ymm20', 'ymm21', 'ymm22', 'ymm23', 'ymm24', 'ymm25', 'ymm26', 'ymm27', 'ymm28', 'ymm29', 'ymm30', 'ymm31', 'zmm0', 'zmm1', 'zmm2', 'zmm3', 'zmm4', 'zmm5', 'zmm6', 'zmm7', 'zmm8', 'zmm9', 'zmm10', 'zmm11', 'zmm12', 'zmm13', 'zmm14', 'zmm15', 'zmm16', 'zmm17', 'zmm18', 'zmm19', 'zmm20', 'zmm21', 'zmm22', 'zmm23', 'zmm24', 'zmm25', 'zmm26', 'zmm27', 'zmm28', 'zmm29', 'zmm30', 'zmm31', 'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d', 'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w', 'bnd0', 'bnd1', 'bnd2', 'bnd3')

_REGISTER: str = rf"(?:%?(?:{'|'.join(REGISTERS)}))"

_SEGMENT_REGISTER: str = rf"(?:%?{'|'.join(SEGMENT_REGISTERS)})"

_SEGMENT_COLON: str = rf"(?:(?P<OP_NUM_PLACEHOLDER_segment>{_SEGMENT_REGISTER})[ \t]*:)"

_LABEL_STATEMENT: str = rf"(?:(?P<label>{_LABEL})[ \t]*:)"

_DIRECTIVE: str = r"(?:\.[a-z._][a-z0-9._]*)"

_INTEL_BASE: str = rf"(?P<OP_NUM_PLACEHOLDER_PERMUTATION_PLACEHOLDER_base>{_REGISTER})"

# XXX: This is wrong because it captures comments.
# XXX: Also, maybe a directive can have a first operand that begins with a ':'
# We enforce this ':' rule to make LABEL_STMT ^ DIRECTIVE_STMT == {}
_DIRECTIVE_STATEMENT: str = rf"(?:(?P<directive>{_DIRECTIVE})(?:[ \t]+[^:].*)?)"

_COMMENT: str = r"(?:#.*)"

_LINE_PREFIX: str = r"\A(?:[ \t]*)"

_LINE_SUFFIX: str = rf"(?:[ \t]*{_COMMENT}?\n?)\Z"

_INSTRUCTION_PREFIX: str = "(?:rep(?:n?[ez])?|lock|notrack|cs|data16|addr32)"

# TODO: FWORD OWORD TBYTE MMWORD and so on
_INTEL_WIDTH: str = r"(?:(?:byte|word|dword|qword|xmmword|ymmword|zmmword)(?:[ \t]+ptr)?)"

_INTEL_MEMORY_OPERAND_MODIFIER: str = rf"(?:{_INTEL_WIDTH}|offset)"

# XXX: This is intentional; GNU asm legitimately allows multiple WIDTH PTR pairs.
_INTEL_MEMORY_OPERAND_MODIFIER_SEQUENCE: str = rf"(?:(?:{_INTEL_MEMORY_OPERAND_MODIFIER}(?:[ \t]+{_INTEL_MEMORY_OPERAND_MODIFIER})*)?)"

_INTEL_INDEX_SCALE: str = rf"(?:(?:\+[ \t]*)*(?P<OP_NUM_PLACEHOLDER_PERMUTATION_PLACEHOLDER_index>{_REGISTER})(?:[ \t]*\*[ \t]*(?P<OP_NUM_PLACEHOLDER_PERMUTATION_PLACEHOLDER_scale>(?:0x)?(?:1|2|4|8)))?)"

def intel_permute_ea() -> list[str]:
    permutations: list[list[str]] = [
        [_INTEL_BASE],
        [_INTEL_BASE, _INTEL_INDEX_SCALE, _INTEL_DISPLACEMENT],
        [_INTEL_INDEX_SCALE, _INTEL_BASE, _INTEL_DISPLACEMENT],
        [_INTEL_BASE, _INTEL_DISPLACEMENT],
        [_INTEL_INDEX_SCALE, _INTEL_DISPLACEMENT],
        [_INTEL_DISPLACEMENT],
        [_INTEL_DISPLACEMENT, _INTEL_BASE, _INTEL_INDEX_SCALE],
        [_INTEL_DISPLACEMENT, _INTEL_INDEX_SCALE, _INTEL_BASE],
        [_INTEL_DISPLACEMENT, _INTEL_BASE],
    ]
    return [r'[ \t\]\[+]*'.join(p).replace("PERMUTATION_PLACEHOLDER", f"permutation_{i}") for i, p in enumerate(permutations)]

_INTEL_EFFECTIVE_ADDRESS: str = rf"(?:(?:{_SEGMENT_COLON}[ \t]*)?(?:[ \t]*(?P<OP_NUM_PLACEHOLDER_preceding_brackets>[\[\]]+)?[ \t]*)?(?:{'|'.join(intel_permute_ea())})(?:[ \t]*(?P<OP_NUM_PLACEHOLDER_trailing_brackets>[\[\]]+)?)?)"

# XXX: This will allow `offset qword ptrfs:0x10`
_INTEL_MEMORY_OPERAND: str = rf"(?:(?:{_INTEL_MEMORY_OPERAND_MODIFIER_SEQUENCE}[ \t]*)?{_INTEL_EFFECTIVE_ADDRESS})"

_INTEL_OPERAND_1: str = rf"(?:{_IMMEDIATE}|{_REGISTER}|{_LABEL}|{_INTEL_MEMORY_OPERAND})".replace("OP_NUM_PLACEHOLDER", "operand_1")
_INTEL_OPERAND_2: str = rf"(?:{_IMMEDIATE}|{_REGISTER}|{_LABEL}|{_INTEL_MEMORY_OPERAND})".replace("OP_NUM_PLACEHOLDER", "operand_2")
_INTEL_OPERAND_3: str = rf"(?:{_IMMEDIATE}|{_REGISTER}|{_LABEL}|{_INTEL_MEMORY_OPERAND})".replace("OP_NUM_PLACEHOLDER", "operand_3")

# XXX: This allows any number of instruction prefixes
_INTEL_INSTRUCTION_STATEMENT: str = rf"(?:(?:{_INSTRUCTION_PREFIX}[ \t]+)*{_MNEMONIC}(?:[ \t]+(?P<operand_1>{_INTEL_OPERAND_1})(?:[ \t]*,[ \t]*(?P<operand_2>{_INTEL_OPERAND_2})(?:[ \t]*,[ \t]*(?P<operand_3>{_INTEL_OPERAND_3}))?)?)?)"

_SCALE: str = r"(?:(?:0x)?(?:1|2|4|8))"

_INTEL_LINE: str = rf"(?i)(?:{_LINE_PREFIX}(?:{_LABEL_STATEMENT}|{_DIRECTIVE_STATEMENT}|{_INTEL_INSTRUCTION_STATEMENT})?{_LINE_SUFFIX})"

_ATT_INDEX_SCALE: str = rf"(?:(?:\+[ \t]*)*(?P<OP_NUM_PLACEHOLDER_PERMUTATION_PLACEHOLDER_index>{_REGISTER})(?:[ \t]*,[ \t]*(?P<OP_NUM_PLACEHOLDER_PERMUTATION_PLACEHOLDER_scale>{_SCALE}))?)"

_ATT_MEMORY_OPERAND: str = rf"(?:(?:{_SEGMENT_COLON}[ \t]*)?(?:[ \t]*(?P<OP_NUM_PLACEHOLDER_direct_jump>\*)[ \t]*)?(?:(?P<OP_NUM_PLACEHOLDER_displacement>{_CONSTANT_EXPRESSION})[ \t]*)?(?:\(?[ \t]*(?P<OP_NUM_PLACEHOLDER_base>{_REGISTER})?(?:[ \t]*,[ \t]*(?:(?P<OP_NUM_PLACEHOLDER_index>{_REGISTER})([ \t]*,[ \t]*(?P<OP_NUM_PLACEHOLDER_scale>{_SCALE})?)?)?)?)?[ \t]*\)?)"

_ATT_OPERAND_1: str = rf"(?:{_IMMEDIATE}|{_REGISTER}|{_LABEL}|{_ATT_MEMORY_OPERAND})".replace("OP_NUM_PLACEHOLDER", "operand_1")
_ATT_OPERAND_2: str = rf"(?:{_IMMEDIATE}|{_REGISTER}|{_LABEL}|{_ATT_MEMORY_OPERAND})".replace("OP_NUM_PLACEHOLDER", "operand_2")
_ATT_OPERAND_3: str = rf"(?:{_IMMEDIATE}|{_REGISTER}|{_LABEL}|{_ATT_MEMORY_OPERAND})".replace("OP_NUM_PLACEHOLDER", "operand_3")

# XXX: This allows any number of instruction prefixes
_ATT_INSTRUCTION_STATEMENT: str = rf"(?:(?:{_INSTRUCTION_PREFIX}[ \t]+)*{_MNEMONIC}(?:[ \t]+(?P<operand_1>{_ATT_OPERAND_1})(?:[ \t]*,[ \t]*(?P<operand_2>{_ATT_OPERAND_2})(?:[ \t]*,[ \t]*(?P<operand_3>{_ATT_OPERAND_3}))?)?)?)"

_ATT_LINE: str = rf"(?i)(?:{_LINE_PREFIX}(?:{_LABEL_STATEMENT}|{_DIRECTIVE_STATEMENT}|{_ATT_INSTRUCTION_STATEMENT})?{_LINE_SUFFIX})"

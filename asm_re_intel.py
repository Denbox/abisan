from asm_re import _MNEMONIC, _HEX_NUMBER, _DEC_NUMBER, _BIN_NUMBER, _CHAR_CONSTANT, _SEGMENT_REGISTER, _REGISTER, _LABEL, _LABEL_STATEMENT, _DIRECTIVE_STATEMENT, _LINE_PREFIX, _LINE_SUFFIX, _OFFSET

_IMMEDIATE: str = rf"(?:{_HEX_NUMBER}|{_DEC_NUMBER}|{_BIN_NUMBER}|{_CHAR_CONSTANT})"

_PTR: str = r"(?:ptr)"

# TODO: FWORD OWORD TBYTE MMWORD and so on.
_WIDTH: str = rf"(?:(?:byte|word|dword|qword|xmmword|ymmword|zmmword)(?:[ \t]+{_PTR})?)"

_MEMORY_OPERAND_MODIFIER: str = rf"(?:{_WIDTH}|{_OFFSET})"

# XXX: This is intentional; GNU asm legitimately allows multiple WIDTH PTR pairs.
_MEMORY_OPERAND_MODIFIER_SEQUENCE: str = rf"(?:(?:{_MEMORY_OPERAND_MODIFIER}(?:[ \t]+{_MEMORY_OPERAND_MODIFIER})*)?)"

_CONSTANT: str = rf"(?:{_LABEL}|{_IMMEDIATE})"

_OPERATOR: str = r"(?:[-+*/^&<>%|!]|<<|>>)"

_CONSTANT_EXPRESSION: str = rf"(?:(?:{_CONSTANT}(?:[ \t]*{_OPERATOR}[ \t]*{_CONSTANT})*)?)"

_SEGMENT_COLON: str = rf"(?:(?P<OP_NUM_PLACEHOLDER_segment>{_SEGMENT_REGISTER})[ \t]*:)"

_INDEX_SCALE: str = rf"(?:(?:\+[ \t]*)*(?P<OP_NUM_PLACEHOLDER_PERMUTATION_PLACEHOLDER_index>{_REGISTER})(?:[ \t]*\*[ \t]*(?P<OP_NUM_PLACEHOLDER_PERMUTATION_PLACEHOLDER_scale>(?:0x)?(?:1|2|4|8|)))?)"

# Do base and displacement even need to be separated out?
_BASE: str = rf"(?P<OP_NUM_PLACEHOLDER_PERMUTATION_PLACEHOLDER_base>{_REGISTER})"

_DISPLACEMENT: str = rf"(?P<OP_NUM_PLACEHOLDER_PERMUTATION_PLACEHOLDER_displacement>{_CONSTANT_EXPRESSION})"

def permute_ea() -> list[str]:
    permutations: list[list[str]] = [
        [_BASE],
        [_BASE, _INDEX_SCALE, _DISPLACEMENT],
        [_INDEX_SCALE],
        [_INDEX_SCALE, _BASE, _DISPLACEMENT],
        [_BASE, _DISPLACEMENT],
        [_INDEX_SCALE, _DISPLACEMENT],
        [_DISPLACEMENT],
        [_DISPLACEMENT, _BASE, _INDEX_SCALE],
    ]
    return [r'[ \t\]\[+]*'.join(p).replace("PERMUTATION_PLACEHOLDER", f"permutation_{i}") for i, p in enumerate(permutations)]

# TODO: All the other forms of memory operands
_EFFECTIVE_ADDRESS: str = rf"(?:(?:{_SEGMENT_COLON}[ \t]*)?[\[\] \t]*(?:{'|'.join(permute_ea())})[\[\] \t]*)"

# XXX: This will allow `offset qword ptrfs:0x10`
_MEMORY_OPERAND: str = rf"(?:(?:{_MEMORY_OPERAND_MODIFIER_SEQUENCE}[ \t]*)?{_EFFECTIVE_ADDRESS})"

_OPERAND_1: str = rf"(?:{_IMMEDIATE}|{_REGISTER}|{_LABEL}|{_MEMORY_OPERAND})".replace("OP_NUM_PLACEHOLDER", "operand_1")
_OPERAND_2: str = rf"(?:{_IMMEDIATE}|{_REGISTER}|{_LABEL}|{_MEMORY_OPERAND})".replace("OP_NUM_PLACEHOLDER", "operand_2")
_OPERAND_3: str = rf"(?:{_IMMEDIATE}|{_REGISTER}|{_LABEL}|{_MEMORY_OPERAND})".replace("OP_NUM_PLACEHOLDER", "operand_3")

_INSTRUCTION_PREFIX: str = "(?:rep(?:n?[ez])?|lock|notrack|cs|data16|addr32)"

# XXX: This allows any number of instruction prefixes
_INSTRUCTION_STATEMENT: str = rf"(?:(?:{_INSTRUCTION_PREFIX}[ \t]+)*{_MNEMONIC}(?:[ \t]+(?P<operand_1>{_OPERAND_1})(?:[ \t]*,[ \t]*(?P<operand_2>{_OPERAND_2})(?:[ \t]*,[ \t]*(?P<operand_3>{_OPERAND_3}))?)?)?)"

_LINE: str = rf"(?i)(?:{_LINE_PREFIX}(?:{_LABEL_STATEMENT}|{_DIRECTIVE_STATEMENT}|{_INSTRUCTION_STATEMENT})?{_LINE_SUFFIX})"

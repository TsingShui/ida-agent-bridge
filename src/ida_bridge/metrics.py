import re
from typing import Any

_DECL_RE = re.compile(
    r'^\s*(_[A-Z]+\s*[\*\(]|unsigned\s+|signed\s+|__int\d+|int\s|char\s|void\s+\*|float\s|double\s|bool\s|struct\s|enum\s)'
)
_CONTROL_RE = re.compile(r'\b(if|else|for|while|switch|case|return|goto|break|continue)\b')
_CALL_RE = re.compile(r'\b\w+\s*\(')
_STRING_RE = re.compile(r'"[^"]*"')
_OPAQUE_RE = re.compile(r'\b(byte_|unk_)[0-9A-Fa-f]+')

_BITOP_MNEMONICS = frozenset({
    'EOR', 'ORR', 'AND', 'BIC', 'EON', 'ORN',
    'LSL', 'LSR', 'ASR', 'ROR',
    'RBIT', 'REV', 'REV16', 'REV32',
})
_XOR_MNEMONICS = frozenset({'EOR', 'BIC', 'EON'})


def _sanitize(name: str, maxlen: int = 200) -> str:
    for ch in '<>:"/\\|?*.':
        name = name.replace(ch, '_')
    return name[:maxlen]


def analyze_body(body: str) -> dict[str, Any]:
    logic_lines = control_flow = total_calls = string_refs = opaque_refs = 0
    for line in body.splitlines():
        s = line.strip()
        if not s or s in ('{', '}'):
            continue
        if _DECL_RE.match(s):
            continue
        logic_lines += 1
        control_flow += len(_CONTROL_RE.findall(s))
        total_calls += len(_CALL_RE.findall(s))
        string_refs += len(_STRING_RE.findall(s))
        opaque_refs += len(_OPAQUE_RE.findall(s))
    ll = max(logic_lines, 1)
    return {
        'logic_lines': logic_lines,
        'branch_density': round(control_flow / ll, 3),
        'call_density': round(total_calls / ll, 3),
        'string_density': round(string_refs / ll, 3),
        'opaque_density': round(opaque_refs / ll, 3),
    }


def insn_metrics(func) -> dict[str, Any]:
    import ida_ua
    import idautils
    insn = ida_ua.insn_t()  # ty:ignore[missing-argument]
    total = bitops = xors = 0
    for head in idautils.FuncItems(func.start_ea):
        if ida_ua.decode_insn(insn, head):
            total += 1
            mnem = insn.get_canon_mnem().upper()
            if mnem in _BITOP_MNEMONICS:
                bitops += 1
            if mnem in _XOR_MNEMONICS:
                xors += 1
    return {
        'total_insns': total,
        'bitop_density': round(bitops / total, 3) if total else 0,
        'xor_density': round(xors / total, 3) if total else 0,
    }

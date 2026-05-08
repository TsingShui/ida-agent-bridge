from . import resolve
import re

_HEX_BYTE = re.compile(r'^[0-9a-fA-F]{1,2}$')
_ADDR = re.compile(r'^(0x[0-9a-fA-F]+|\d+)$')


def run_sb(db, parts):
    if len(parts) < 2:
        return "usage: !sb <hex bytes> [start] [end]  e.g. !sb 01 14 40 f9"
    # 地址参数必须以 0x 开头或是纯数字，hex byte 是 1-2 位十六进制
    # 从后往前找地址参数，剩余全是 pattern
    rest = parts[1:]
    end_str = start_str = None
    if len(rest) >= 2 and _ADDR.match(rest[-1]) and _ADDR.match(rest[-2]):
        start_str, end_str = rest[-2], rest[-1]
        rest = rest[:-2]
    elif len(rest) >= 1 and _ADDR.match(rest[-1]) and not _HEX_BYTE.match(rest[-1]):
        start_str = rest[-1]
        rest = rest[:-1]
    try:
        pattern = bytes.fromhex("".join(rest))
    except ValueError:
        return f"invalid hex pattern: {' '.join(rest)!r}"
    if not pattern:
        return "usage: !sb <hex bytes> [start] [end]  e.g. !sb 01 14 40 f9"
    start_ea = resolve(db, start_str) if start_str else None
    end_ea = resolve(db, end_str) if end_str else None
    results = db.bytes.find_binary_sequence(pattern, start_ea=start_ea, end_ea=end_ea)
    if not results:
        return "(no matches)"
    lines = []
    for ea in results:
        func = db.functions.get_at(ea)
        if func:
            func_name = db.functions.get_name(func)
            offset = ea - func.start_ea
            col = f"0x{ea:x}  {func_name}+0x{offset:x}  [in: {func_name}]"
        else:
            col = f"0x{ea:x}  (no function)"
        lines.append(col)
    lines.append(f"\n{len(results)} match(es)")
    return "\n".join(lines)

from . import resolve


def run_hd(db, parts):
    if len(parts) < 2:
        return "usage: !hd <addr|name> [n=64]"
    ea = resolve(db, parts[1])
    n = int(parts[2]) if len(parts) > 2 else 64
    import ida_bytes
    data = ida_bytes.get_bytes(ea, n)
    if not data:
        return f"no bytes at 0x{ea:x}"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        asc_part = "".join(chr(b) if 0x20 <= b < 0x7f else "." for b in chunk)
        lines.append(f"0x{ea + i:x}  {hex_part:<47}  {asc_part}")
    return "\n".join(lines)

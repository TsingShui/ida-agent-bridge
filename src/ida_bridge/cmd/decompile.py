from . import resolve


def _strip_vars(lines: list[str]) -> list[str]:
    import re
    _decl = re.compile(r'^\s+[\w\s\*]+\w+;\s*(//.*)?$')
    in_decl_block = False
    result = []
    for line in lines:
        if not in_decl_block:
            if line.strip() == '{':
                in_decl_block = True
                result.append(line)
                continue
        else:
            if _decl.match(line):
                continue
            in_decl_block = False
            if not line.strip():  # 跳过声明块后的空行
                continue
        result.append(line)
    return result


def run_pdc(db, parts):
    if len(parts) < 2:
        return "usage: !pdc <addr|name> [-s]"
    ea = resolve(db, parts[1])
    func = db.functions.get_at(ea)
    if func is None:
        return f"no function at 0x{ea:x}"
    strip = "-s" in parts
    from ida_domain.microcode import DecompilationFlags
    pseudo = db.pseudocode.decompile(func, flags=DecompilationFlags.NO_CACHE)
    text_lines = pseudo.to_text() or ["(no pseudocode)"]
    if strip:
        text_lines = _strip_vars(text_lines)
    return "\n".join([f"; {db.functions.get_name(func)} @ 0x{func.start_ea:x}"] + text_lines)


def run_mc(db, parts):
    if len(parts) < 2:
        return "usage: !mc <addr|name> [maturity]"
    ea = resolve(db, parts[1])
    func = db.functions.get_at(ea)
    if func is None:
        return f"no function at 0x{ea:x}"
    from ida_domain.microcode import MicroMaturity
    _maturity_map = {
        "generated": MicroMaturity.GENERATED,
        "preopt":    MicroMaturity.PREOPTIMIZED,
        "locopt":    MicroMaturity.LOCOPT,
        "calls":     MicroMaturity.CALLS,
        "glbopt1":   MicroMaturity.GLBOPT1,
        "glbopt2":   MicroMaturity.GLBOPT2,
        "glbopt3":   MicroMaturity.GLBOPT3,
        "lvars":     MicroMaturity.LVARS,
    }
    key = parts[2].lower() if len(parts) > 2 else "generated"
    if key not in _maturity_map:
        return f"unknown maturity '{key}', choose: {', '.join(_maturity_map)}"
    lines = db.microcode.get_text(func, maturity=_maturity_map[key])
    return "\n".join(lines) if lines else "(no microcode)"

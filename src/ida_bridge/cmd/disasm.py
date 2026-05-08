from . import resolve


def run_pd(db, parts):
    if len(parts) < 2:
        return "usage: !pd <addr|name> [n=16]"
    ea = resolve(db, parts[1])
    n = int(parts[2]) if len(parts) > 2 else 16
    lines = []
    cur = ea
    for _ in range(n):
        insn = db.instructions.get_at(cur)
        if insn is None:
            break
        lines.append(f"0x{insn.ea:x}  {db.instructions.get_disassembly(insn)}")
        cur = insn.ea + insn.size
    return "\n".join(lines) if lines else f"no instruction at 0x{ea:x}"


def run_pdf(db, parts):
    if len(parts) < 2:
        return "usage: !pdf <addr|name>"
    ea = resolve(db, parts[1])
    func = db.functions.get_at(ea)
    if func is None:
        return f"no function at 0x{ea:x}"
    fc = db.functions.get_flowchart(func)
    block_starts = {b.start_ea: b for b in fc}
    block_end_insn = {}
    for b in fc:
        if b.start_ea >= b.end_ea:
            continue
        insns = list(b.get_instructions())
        if insns:
            block_end_insn[insns[-1].ea] = b
    lines = []
    for insn in db.functions.get_instructions(func):
        if insn.ea in block_starts:
            b = block_starts[insn.ea]
            lines.append(f"; block {b.id}  [0x{b.start_ea:x} - 0x{b.end_ea:x}]")
        disasm = db.instructions.get_disassembly(insn)
        line = f"0x{insn.ea:x}  {disasm}"
        if insn.ea in block_end_insn:
            b = block_end_insn[insn.ea]
            succs = list(b.get_successors())
            succ_eas = {s.start_ea for s in succs}
            if len(succs) == 1:
                line += f"    ; → 0x{succs[0].start_ea:x}"
            elif len(succs) == 2:
                taken_ea = fall_ea = None
                for xref in db.xrefs.from_ea(insn.ea):
                    if xref.is_jump and xref.to_ea in succ_eas:
                        taken_ea = xref.to_ea
                    elif xref.is_flow and xref.to_ea in succ_eas:
                        fall_ea = xref.to_ea
                if taken_ea and fall_ea:
                    line += f"    ; true→ 0x{taken_ea:x}  false→ 0x{fall_ea:x}"
                else:
                    line += "    ; " + "  ".join(f"→ 0x{s.start_ea:x}" for s in succs)
        lines.append(line)
    return "\n".join(lines)


def run_deps(db, parts):
    if len(parts) < 2:
        return "usage: !deps <addr|name> [depth=3]"
    ea = resolve(db, parts[1])
    func = db.functions.get_at(ea)
    if func is None:
        return f"no function at 0x{ea:x}"
    max_depth = int(parts[2]) if len(parts) > 2 else 3
    lines: list[str] = []

    def _walk(f, depth, visited):
        indent = "  " * depth
        name = db.functions.get_name(f)
        lines.append(f"{indent}{name}  [0x{f.start_ea:x}]")
        if depth >= max_depth or f.start_ea in visited:
            if list(db.functions.get_callees(f)):
                lines.append(f"{indent}  ...")
            return
        visited.add(f.start_ea)
        for callee in db.functions.get_callees(f):
            _walk(callee, depth + 1, visited)

    _walk(func, 0, set())
    return "\n".join(lines)

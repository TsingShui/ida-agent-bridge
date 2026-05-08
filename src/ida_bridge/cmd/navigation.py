from . import resolve


def run_afl(db, parts):
    pat = parts[1].lower() if len(parts) > 1 else None
    lines = []
    for func in db.functions.get_all():
        name = db.functions.get_name(func)
        if pat is None or pat in name.lower():
            size = func.end_ea - func.start_ea
            callers = len(list(db.functions.get_callers(func)))
            lines.append(f"0x{func.start_ea:x}\t{name}\t{size:#x}\tcallers={callers}")
    return "\n".join(lines) if lines else "(no results)"


def run_afi(db, parts):
    if len(parts) < 2:
        return "usage: !afi <addr|name>"
    ea = resolve(db, parts[1])
    func = db.functions.get_at(ea)
    if func is None:
        return f"no function at 0x{ea:x}"
    name = db.functions.get_name(func)
    size = func.end_ea - func.start_ea
    callers = list(db.functions.get_callers(func))
    callees = list(db.functions.get_callees(func))
    comment = db.functions.get_comment(func) or ""
    lines = [
        f"name:     {name}",
        f"addr:     0x{func.start_ea:x} - 0x{func.end_ea:x}",
        f"size:     {size:#x} ({size})",
    ]
    if comment:
        lines.append(f"comment:  {comment}")
    lines.append(f"callers:  {len(callers)}")
    for c in callers:
        lines.append(f"  0x{c.start_ea:x}  {db.functions.get_name(c)}")
    lines.append(f"callees:  {len(callees)}")
    for c in callees:
        lines.append(f"  0x{c.start_ea:x}  {db.functions.get_name(c)}")
    return "\n".join(lines)


def run_iz(db, parts):
    pat = parts[1].lower() if len(parts) > 1 else None
    lines = []
    for s in db.strings:
        text = str(s)
        if pat is None or pat in text.lower():
            refs = list(db.xrefs.data_refs_to_ea(s.address))
            ref_funcs = []
            seen: set = set()
            for src in refs:
                f = db.functions.get_at(src)
                fn = db.functions.get_name(f) if f else hex(src)
                if fn not in seen:
                    seen.add(fn)
                    ref_funcs.append(fn)
            ref_str = (f"  refs={len(refs)}  [{', '.join(ref_funcs[:5])}"
                       f"{'...' if len(ref_funcs) > 5 else ''}]") if refs else ""
            lines.append(f"0x{s.address:x}\t{text}{ref_str}")
    return "\n".join(lines) if lines else "(no results)"


def run_axi(db, parts):
    if len(parts) < 2:
        return "usage: !axi <import_name>"
    name = parts[1]
    imp = db.imports.get_import_by_name(name)
    if imp is None:
        imp = next((i for i in db.imports.get_all_imports()
                    if i.name == name or i.name.startswith(name + "@@")), None)
    if imp is None:
        return f"import not found: {name}"
    lines = []
    for src in db.xrefs.calls_to_ea(imp.address):
        caller = db.functions.get_at(src)
        caller_name = db.functions.get_name(caller) if caller else "?"
        lines.append(f"0x{src:x}  {caller_name}")
    return "\n".join(lines) if lines else f"(no callers for {imp.module_name}!{imp.name})"

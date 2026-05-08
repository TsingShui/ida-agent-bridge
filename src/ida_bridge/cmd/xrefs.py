from . import resolve


def run_xrefs(db, parts):
    cmd = parts[0].lower()
    if len(parts) < 2:
        return f"usage: {cmd} <addr|name>"
    ea = resolve(db, parts[1])
    lines = []
    if cmd == "!axt":
        for xref in db.xrefs.to_ea(ea):
            sym = db.names.get_at(xref.from_ea) or ""
            func = db.functions.get_at(xref.from_ea)
            fn = f"[in: {db.functions.get_name(func)}]" if func else ""
            lines.append(f"0x{xref.from_ea:x}  {sym}  {xref.type.name}  {fn}")
    else:
        for xref in db.xrefs.from_ea(ea):
            sym = db.names.get_at(xref.to_ea) or ""
            func = db.functions.get_at(xref.to_ea)
            fn = f"[func: {db.functions.get_name(func)}]" if func else ""
            lines.append(f"0x{xref.to_ea:x}  {sym}  {xref.type.name}  {fn}")
    return "\n".join(lines) if lines else "(no xrefs)"

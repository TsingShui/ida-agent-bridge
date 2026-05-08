from . import resolve


def run_ca(db, parts):
    if len(parts) < 3:
        return "usage: !ca <addr> <text>"
    ea = resolve(db, parts[1])
    db.comments.set_at(ea, " ".join(parts[2:]))
    return f"comment set @ 0x{ea:x}"


def run_cc(db, parts):
    if len(parts) < 3:
        return "usage: !cc <addr|name> <text>"
    ea = resolve(db, parts[1])
    func = db.functions.get_at(ea)
    if func is None:
        return f"no function at 0x{ea:x}"
    db.functions.set_comment(func, " ".join(parts[2:]))
    return f"comment set @ 0x{ea:x}"


def run_afn(db, parts):
    if len(parts) < 3:
        return "usage: !afn <addr|name> <new_name>"
    ea = resolve(db, parts[1])
    func = db.functions.get_at(ea)
    if func is None:
        return f"no function at 0x{ea:x}"
    old_name = db.functions.get_name(func)
    db.functions.set_name(func, parts[2])
    return f"renamed 0x{ea:x}: {old_name} → {parts[2]}"

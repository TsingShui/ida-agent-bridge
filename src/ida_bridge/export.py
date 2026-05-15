import json
import os
import zlib
import logging
import shutil
from typing import Any
from .metrics import analyze_body, insn_metrics

logger = logging.getLogger(__name__)

MAX_FUNC_SIZE = 16 * 1024
MAX_FUNC_INSNS = 3000


def func_hash(db, func) -> str:
    c = zlib.crc32((db.functions.get_name(func) or "").encode())
    c = zlib.crc32((db.functions.get_comment(func) or "").encode(), c)
    c = zlib.crc32((db.functions.get_comment(func, repeatable=True) or "").encode(), c)
    size = func.end_ea - func.start_ea
    c = zlib.crc32(db.bytes.get_bytes_at(func.start_ea, size), c)
    return format(c & 0xFFFFFFFF, '08x')


def _addr_list(funcs) -> str:
    return ",".join(hex(f.start_ea) for f in funcs) if funcs else "none"


def _func_file(func_ea: int) -> str:
    return f"decompile/{func_ea:X}.c"


_HASH_INDEX = "hash_index.json"
_EXPORT_CONFIG = "export_config.json"


def _read_hash_index(export_dir: str) -> dict[int, str]:
    path = os.path.join(export_dir, _HASH_INDEX)
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return {int(k, 16): v for k, v in raw.items()}


def _write_hash_index(export_dir: str, index: dict[int, str]) -> None:
    path = os.path.join(export_dir, _HASH_INDEX)
    raw = {format(ea, 'x'): h for ea, h in sorted(index.items())}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(raw, f)


def _read_export_config(export_dir: str) -> dict:
    path = os.path.join(export_dir, _EXPORT_CONFIG)
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _write_export_config(export_dir: str, config: dict) -> None:
    path = os.path.join(export_dir, _EXPORT_CONFIG)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)


def _write_func(export_dir: str, func_ea: int, func_name: str, body: str,
                callers, callees, fallback_reason: str | None, *,
                func_hash: str | None = None,
                comment: str | None = None) -> str:
    out_file = _func_file(func_ea)
    path = os.path.join(export_dir, out_file)
    lines = [
        "/*",
        f" * func-name: {func_name}",
        f" * func-address: {hex(func_ea)}",
    ]
    if func_hash is not None:
        lines.append(f" * func-hash: {func_hash}")
    lines += [
        f" * callers: {_addr_list(callers)}",
        f" * callees: {_addr_list(callees)}",
    ]
    if comment:
        lines.append(f" * comment: {comment}")
    if fallback_reason:
        lines.append(f" * fallback-reason: {fallback_reason}")
    lines += [" */", "", body]
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out_file


_INDEX_HEADER = ("addr\tname\tlogic_lines\tbranch_density\tcall_density\tstring_density\t"
                 "opaque_density\ttotal_insns\tbitop_density\txor_density\tcaller_count\tfile\tcallers\tcallees")


def _format_index_row(ea, name, metrics, out_file, callers, callees) -> str:
    return (
        f"{ea:#x}\t{name}\t"
        f"{metrics['logic_lines']}\t{metrics['branch_density']}\t"
        f"{metrics['call_density']}\t{metrics['string_density']}\t"
        f"{metrics.get('opaque_density', 0)}\t"
        f"{metrics.get('total_insns', 0)}\t{metrics.get('bitop_density', 0)}\t"
        f"{metrics.get('xor_density', 0)}\t"
        f"{len(callers)}\t{out_file}\t{_addr_list(callers)}\t{_addr_list(callees)}"
    )


def _write_index(export_dir: str, rows: list) -> None:
    path = os.path.join(export_dir, "function_index.tsv")
    with open(path, "w", encoding="utf-8") as f:
        f.write(_INDEX_HEADER + "\n")
        for row in rows:
            f.write(_format_index_row(*row) + "\n")


def _patch_index(export_dir: str, updated_rows: list, remove_eas: set[int] | None = None) -> None:
    path = os.path.join(export_dir, "function_index.tsv")
    existing: dict[int, str] = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.startswith("addr\t"):
                    continue
                parts = line.split("\t")
                try:
                    ea = int(parts[0], 16)
                    existing[ea] = line
                except (ValueError, IndexError):
                    pass

    for row in updated_rows:
        ea = row[0]
        existing[ea] = _format_index_row(*row)
    for ea in (remove_eas or set()):
        existing.pop(ea, None)

    with open(path, "w", encoding="utf-8") as f:
        f.write(_INDEX_HEADER + "\n")
        for line in existing.values():
            f.write(line + "\n")


_EMPTY_METRICS = {
    'logic_lines': 0, 'branch_density': 0, 'call_density': 0,
    'string_density': 0, 'opaque_density': 0,
    'total_insns': 0, 'bitop_density': 0, 'xor_density': 0,
}


def _export_single_func(db, export_dir: str, ea: int,
                        digest: str | None = None,
                        compute_metrics: bool = True) -> tuple | None:
    func = db.functions.get_at(ea)
    if func is None:
        logger.warning("function not found at %#x", ea)
        return None

    func_name = func.name or hex(ea)
    callers = db.functions.get_callers(func)
    callees = db.functions.get_callees(func)
    comment = db.functions.get_comment(func) or None

    fallback_reason = None
    body = None

    func_size = func.end_ea - func.start_ea
    im = insn_metrics(func) if compute_metrics else {}
    if func_size > MAX_FUNC_SIZE:
        fallback_reason = f"too large ({func_size} bytes)"
    elif compute_metrics and im['total_insns'] > MAX_FUNC_INSNS:
        fallback_reason = f"too many insns ({im['total_insns']})"

    if fallback_reason is None:
        try:
            from ida_domain.pseudocode import DecompilationFlags
            decomp = db.pseudocode.decompile(func, DecompilationFlags.NO_CACHE)
            lines = decomp.to_text(remove_tags=True)
            body = "\n".join(lines) if lines else None
            if body is None:
                fallback_reason = "empty pseudocode"
        except Exception as e:
            fallback_reason = str(e)

    if body is None:
        sig = db.functions.get_signature(func)
        body = (f"{sig} {{\n    /* IDA Cannot Decompile: {fallback_reason} */\n}}"
                if sig else
                f"void {func_name}() {{\n    /* IDA Cannot Decompile: {fallback_reason} */\n}}")

    out_file = _write_func(export_dir, ea, func_name, body, callers, callees,
                           fallback_reason, func_hash=digest, comment=comment)
    if compute_metrics:
        metrics = analyze_body(body)
        metrics.update(im)
    else:
        metrics = dict(_EMPTY_METRICS)
    return (ea, func_name, metrics, out_file, callers, callees)


def export_strings(db, export_dir: str) -> None:
    path = os.path.join(export_dir, "strings.tsv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("addr\tencoding\tcontents\n")
        for s in db.strings.get_all():
            enc = s.encoding or "utf-8"
            if enc.upper() in ("MUTF-8", "MUTF8"):
                enc = "utf-8"
            text = s.contents.decode(enc, errors="replace").replace("\n", "\\n").replace("\r", "\\r")
            f.write(f"{s.address:#x}\t{enc}\t{text}\n")


def export_imports(db, export_dir: str) -> None:
    path = os.path.join(export_dir, "imports.tsv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("addr\tmodule\tname\n")
        for imp in db.imports.get_all_imports():
            f.write(f"{imp.address:#x}\t{imp.module_name or ''}\t{imp.name or ''}\n")


def export_exports(db, export_dir: str) -> None:
    import ida_entry
    path = os.path.join(export_dir, "exports.tsv")
    with open(path, "w", encoding="utf-8") as f:
        f.write("addr\tname\n")
        for i in range(ida_entry.get_entry_qty()):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal) or f"ordinal_{ordinal}"
            f.write(f"{ea:#x}\t{name}\n")


def export_functions(db, export_dir: str, compute_metrics: bool = False) -> None:
    import ida_funcs
    os.makedirs(os.path.join(export_dir, "decompile"), exist_ok=True)
    rows = []
    hash_index: dict[int, str] = {}
    all_funcs = list(db.functions.get_all())
    ok = skipped = 0
    for i, func in enumerate(all_funcs):
        raw = ida_funcs.get_func(func.start_ea)
        if raw and (raw.flags & ida_funcs.FUNC_LIB):
            skipped += 1
            continue
        digest = func_hash(db, func)
        hash_index[func.start_ea] = digest
        result = _export_single_func(db, export_dir, func.start_ea, digest=digest,
                                      compute_metrics=compute_metrics)
        if result:
            rows.append(result)
            ok += 1
        if (i + 1) % 100 == 0:
            logger.info("progress: %d/%d (ok=%d skip=%d)", i + 1, len(all_funcs), ok, skipped)
    _write_index(export_dir, rows)
    _write_hash_index(export_dir, hash_index)
    logger.info("functions done: total=%d ok=%d skipped=%d", len(all_funcs), ok, skipped)


def export_incremental(db, export_dir: str, func_addrs: "list[int] | dict[int, str]",
                       compute_metrics: bool = False) -> None:
    import time
    reasons: dict[int, str] = func_addrs if isinstance(func_addrs, dict) else {ea: "" for ea in func_addrs}
    os.makedirs(os.path.join(export_dir, "decompile"), exist_ok=True)
    t0 = time.monotonic()
    hash_index = _read_hash_index(export_dir)
    updated_rows = []
    for ea, reason in reasons.items():
        func = db.functions.get_at(ea)
        digest = func_hash(db, func) if func else None
        if digest:
            hash_index[ea] = digest
        t1 = time.monotonic()
        result = _export_single_func(db, export_dir, ea, digest=digest,
                                      compute_metrics=compute_metrics)
        if result:
            updated_rows.append(result)
            reason_str = f"  [{reason}]" if reason else ""
            logger.info("refreshed %s (%.0fms)%s", result[1], (time.monotonic() - t1) * 1000, reason_str)
    _patch_index(export_dir, updated_rows)
    _write_hash_index(export_dir, hash_index)
    elapsed = time.monotonic() - t0
    logger.info("incremental done: %d/%d in %.2fs", len(updated_rows), len(reasons), elapsed)


def export_all(db, export_dir: str, compute_metrics: bool = False) -> None:
    os.makedirs(export_dir, exist_ok=True)
    decompile_dir = os.path.join(export_dir, "decompile")
    if os.path.isdir(decompile_dir):
        shutil.rmtree(decompile_dir)
    for fname in ("strings.tsv", "imports.tsv", "exports.tsv", "function_index.tsv"):
        p = os.path.join(export_dir, fname)
        if os.path.exists(p):
            os.remove(p)
    _write_export_config(export_dir, {"compute_metrics": compute_metrics})
    export_strings(db, export_dir)
    export_imports(db, export_dir)
    export_exports(db, export_dir)
    export_functions(db, export_dir, compute_metrics=compute_metrics)


def sync_exports(db, export_dir: str, compute_metrics: bool | None = None) -> None:
    import ida_funcs
    import time
    decompile_dir = os.path.join(export_dir, "decompile")

    t0 = time.monotonic()

    if compute_metrics is None:
        config = _read_export_config(export_dir)
        compute_metrics = config.get("compute_metrics", False)

    if not os.path.isdir(decompile_dir):
        logger.info("no prior export found, running full export...")
        export_all(db, export_dir, compute_metrics=compute_metrics)
        logger.info("sync done in %.1fs", time.monotonic() - t0)
        return

    non_lib_eas: set[int] = set()
    for func in db.functions.get_all():
        raw = ida_funcs.get_func(func.start_ea)
        if not (raw and (raw.flags & ida_funcs.FUNC_LIB)):
            non_lib_eas.add(func.start_ea)

    file_hashes = _read_hash_index(export_dir)
    t_read = time.monotonic()
    logger.info("hash index read: %d entries in %.2fs", len(file_hashes), t_read - t0)

    stale: list[int] = []
    for ea in non_lib_eas:
        func = db.functions.get_at(ea)
        if func and file_hashes.get(ea) != func_hash(db, func):
            stale.append(ea)

    t_hash = time.monotonic()
    logger.info("db hash compare: %d funcs in %.2fs, %d stale", len(non_lib_eas), t_hash - t_read, len(stale))

    orphans = [ea for ea in file_hashes if ea not in non_lib_eas]
    for ea in orphans:
        path = os.path.join(export_dir, _func_file(ea))
        if os.path.exists(path):
            os.remove(path)
            logger.info("removed orphan: %s", _func_file(ea))

    if not stale and not orphans:
        logger.info("cache hit, skipping export (total %.2fs)", time.monotonic() - t0)
        return

    if stale:
        logger.info("%d functions changed, running incremental export...", len(stale))
        export_incremental(db, export_dir, stale, compute_metrics=compute_metrics)
    if orphans:
        for ea in orphans:
            file_hashes.pop(ea, None)
        _patch_index(export_dir, [], remove_eas=set(orphans))
        _write_hash_index(export_dir, file_hashes)

    logger.info("sync done in %.1fs", time.monotonic() - t0)


def export_symbols(db, output_path: str) -> int:
    """Export all function symbols as 'offset name' lines for tsrace --sym.

    Format: one line per function, sorted by offset:
        0x12d68c Java_com_xxx_initSdk
        0x134500 sub_134500

    Returns the number of symbols written.
    """
    import ida_nalt
    image_base = ida_nalt.get_imagebase()

    entries = []
    for func in db.functions.get_all():
        name = db.functions.get_name(func)
        offset = func.start_ea - image_base
        entries.append((offset, name))

    entries.sort(key=lambda e: e[0])

    with open(output_path, "w", encoding="utf-8") as f:
        for offset, name in entries:
            f.write(f"0x{offset:x} {name}\n")

    logger.info("symbols exported: %d entries → %s", len(entries), output_path)
    return len(entries)


def parse_addrs(s: str) -> list[int]:
    return [int(p.strip(), 16) for p in s.split(",") if p.strip()]

from . import resolve


def run_syms(db, parts):
    """Export function symbols to a file for tsrace.

    Usage: !syms <output_path>
    Example: !syms /tmp/libmtguard.syms
    """
    if len(parts) < 2:
        return "usage: !syms <output_path>\nexample: !syms /tmp/libmtguard.syms"

    output_path = parts[1]
    from ..export import export_symbols
    count = export_symbols(db, output_path)
    return f"exported {count} symbols → {output_path}"

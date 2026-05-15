#!/usr/bin/env python3
"""ida-syms — Export IDA function symbols for tsrace.

Usage:
    ida-syms <binary_or_i64> [output_path]

Output format (one line per function, sorted by offset):
    0x12d68c Java_com_xxx_initSdk
    0x134500 sub_134500
"""
import sys
import os
import logging

import idapro  # noqa: F401

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger("ida_syms")


def main() -> None:
    if len(sys.argv) < 2:
        print(
            "Usage: ida-syms <binary_or_i64> [output_path]\n"
            "\n"
            "Arguments:\n"
            "  binary_or_i64   binary file or .i64 database\n"
            "  output_path     output symbols file (default: <name>.syms)\n"
            "\n"
            "Examples:\n"
            "  ida-syms libmtguard.so\n"
            "  ida-syms libmtguard.i64 /tmp/libmtguard.syms",
            file=sys.stderr,
        )
        sys.exit(1)

    idb_path = sys.argv[1]

    # Derive default output path
    if len(sys.argv) > 2:
        output_path = sys.argv[2]
    else:
        stem = os.path.basename(idb_path)
        for ext in ('.i64', '.idb', '.so', '.dylib', '.dll', '.exe', '.elf', '.bin', '.out'):
            if stem.endswith(ext):
                stem = stem[:-len(ext)]
                break
        output_path = os.path.join(os.getcwd(), f"{stem}.syms")

    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions

    opts = IdaCommandOptions(auto_analysis=True)
    logger.info("opening %s...", idb_path)

    with Database.open(idb_path, opts) as db:
        import ida_auto
        ida_auto.auto_wait()

        from .export import export_symbols
        count = export_symbols(db, output_path)
        print(f"{count} symbols → {output_path}")


if __name__ == "__main__":
    main()

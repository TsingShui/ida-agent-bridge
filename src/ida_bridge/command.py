import io
import logging
import os
import traceback
import contextlib
from typing import Any

from .cmd import (
    run_afl, run_afi, run_iz, run_axi,
    run_xrefs,
    run_pd, run_pdf, run_deps,
    run_pdc, run_mc,
    run_ca, run_cc, run_afn,
    run_hd, run_sb, run_syms,
)

logger = logging.getLogger(__name__)

HELP = (
    "!iz  [pat]               list strings\n"
    "!afl [pat]               list functions\n"
    "!afi <addr|name>         function details\n"
    "!axt <addr|name>         xrefs to\n"
    "!axf <addr|name>         xrefs from\n"
    "!axi <name>              callers of import symbol\n"
    "!pd  <addr|name> [n=16]  disassemble n instructions\n"
    "!pdf <addr|name>         disassemble whole function\n"
    "!pdc <addr|name> [-s]    pseudocode (-s strips var decls)\n"
    "!deps <addr|name> [d=3]  recursive call chain\n"
    "!cc  <addr|name> <text>  set function comment\n"
    "!ca  <addr> <text>       set address comment\n"
    "!afn <addr|name> <name>  rename function\n"
    "!mc  <addr|name> [maturity]  microcode\n"
    "!hd  <addr|name> [n=64]      hexdump\n"
    "!sb  <hex> [start] [end]     search byte sequence\n"
    "!syms <path>                 export symbols for tsrace\n"
    "!pwd                         working directory\n"
)


def dispatch(db, cmd_line: str) -> str:
    parts = cmd_line.split()
    match parts[0].lower():
        case "!?" | "!help":   return HELP
        case "!afl":           return run_afl(db, parts)
        case "!afi":           return run_afi(db, parts)
        case "!iz":            return run_iz(db, parts)
        case "!axi":           return run_axi(db, parts)
        case "!axt" | "!axf": return run_xrefs(db, parts)
        case "!pd":            return run_pd(db, parts)
        case "!pdf":           return run_pdf(db, parts)
        case "!deps":          return run_deps(db, parts)
        case "!pdc":           return run_pdc(db, parts)
        case "!mc":            return run_mc(db, parts)
        case "!ca":            return run_ca(db, parts)
        case "!cc":            return run_cc(db, parts)
        case "!afn":           return run_afn(db, parts)
        case "!hd":            return run_hd(db, parts)
        case "!sb":            return run_sb(db, parts)
        case "!syms":          return run_syms(db, parts)
        case "!pwd":           return os.getcwd()
        case cmd:              return f"unknown command: {cmd}  (try !?)"


def exec_one(db, ns: dict[str, Any], code: str, hooks=None) -> tuple[bytes, int]:
    buf = io.StringIO()
    exit_code = 0
    cmd = code.strip()
    if cmd.startswith("!"):
        logger.info("cmd: %s", cmd)
    try:
        with contextlib.redirect_stdout(buf):
            if cmd.startswith("!"):
                buf.write(dispatch(db, cmd) + "\n")
            else:
                exec(compile(code, "<exec>", "exec"), ns)
    except Exception:
        buf.write(traceback.format_exc())
        exit_code = 1
    if hooks is not None:
        hooks.flush_patches()
    return buf.getvalue().encode(), exit_code

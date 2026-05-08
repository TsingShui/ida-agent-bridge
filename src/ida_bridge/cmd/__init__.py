import ida_name


def resolve(db, token: str) -> int:
    try:
        return int(token, 0)
    except ValueError:
        ea = ida_name.get_name_ea(0xFFFFFFFFFFFFFFFF, token)
        if ea == 0xFFFFFFFFFFFFFFFF:
            raise ValueError(f"name not found: {token}")
        return ea


from .navigation import run_afl, run_afi, run_iz, run_axi
from .xrefs import run_xrefs
from .disasm import run_pd, run_pdf, run_deps
from .decompile import run_pdc, run_mc
from .edit import run_ca, run_cc, run_afn
from .hexdump import run_hd
from .search import run_sb

__all__ = [
    "resolve",
    "run_afl", "run_afi", "run_iz", "run_axi",
    "run_xrefs",
    "run_pd", "run_pdf", "run_deps",
    "run_pdc", "run_mc",
    "run_ca", "run_cc", "run_afn",
    "run_hd",
    "run_sb",
]

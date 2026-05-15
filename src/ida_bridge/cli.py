#!/usr/bin/env python3
"""ida-bridge — IDA Pro database export and real-time file sync."""
import sys
import os
import logging
from typing import Annotated

import cyclopts

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger("ida_bridge")

app = cyclopts.App(name="ida-bridge", help="IDA Pro database export and real-time REPL server.")

DEFAULT_PORT = 13120
_KNOWN_EXTS = ('.i64', '.idb', '.so', '.dylib', '.dll', '.exe', '.elf', '.bin', '.out')


def _strip_ext(path: str) -> str:
    stem = os.path.basename(path)
    for ext in _KNOWN_EXTS:
        if stem.endswith(ext):
            return stem[:-len(ext)]
    return stem


def _default_export_dir(binary_path: str) -> str:
    return os.path.join(os.getcwd(), f'ida-bridge-{_strip_ext(binary_path)}')


def _open_db(binary: str):
    """Open IDA database, wait for auto-analysis, return context manager."""
    import idapro  # noqa: F401 — initializes IDA Pro runtime
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions
    opts = IdaCommandOptions(auto_analysis=True)
    logger.info("opening %s...", binary)
    return Database.open(binary, opts)


def _check_update_async() -> None:
    import threading

    def _check():
        try:
            import urllib.request, json
            url = "https://api.github.com/repos/TsingShui/ida-agent-bridge/commits/main"
            req = urllib.request.Request(url, headers={"Accept": "application/vnd.github.sha"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                remote_sha = resp.read().decode().strip()

            import subprocess, pathlib
            repo = pathlib.Path(__file__).parent.parent.parent.parent  # src/ida_bridge -> repo root
            result = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repo, capture_output=True, text=True, timeout=5,
            )
            local_sha = result.stdout.strip()
            if local_sha and remote_sha and not remote_sha.startswith(local_sha) and local_sha != remote_sha:
                logger.warning(
                    "ida-agent-bridge has updates: local=%s remote=%s\n"
                    "  run: cd %s && git pull",
                    local_sha[:8], remote_sha[:8], repo,
                )
        except Exception:
            pass

    threading.Thread(target=_check, daemon=True).start()


@app.default
def run(
    binary: Annotated[str, cyclopts.Parameter(help="Binary file or .i64 database to open.")],
    export_dir: Annotated[str, cyclopts.Parameter(help="Output directory (default: ./ida-bridge-<name>/).")] = "",
    port: Annotated[int, cyclopts.Parameter(help="REPL port.")] = DEFAULT_PORT,
    *,
    human_shell: Annotated[bool, cyclopts.Parameter(help="Enable human interactive shell on port+1.")] = False,
    skip_export: Annotated[bool, cyclopts.Parameter(help="Skip export and hooks, start REPL only.")] = False,
) -> None:
    """Open a binary in IDA, export functions, and start a REPL server."""
    _check_update_async()

    if not export_dir:
        export_dir = _default_export_dir(binary)

    shell_port = port + 1 if human_shell else None

    from .hooks import AutoSyncHooks
    from .repl import serve

    import socket as _socket
    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as _s:
        if _s.connect_ex(("127.0.0.1", port)) == 0:
            print(f"error: port {port} already in use, another ida-bridge may be running", file=sys.stderr)
            sys.exit(1)

    base = os.path.splitext(binary)[0]
    locked = [f"{base}.{ext}" for ext in ("id0", "id1", "id2", "nam", "til")
              if os.path.isfile(f"{base}.{ext}")]
    if locked:
        print(f"error: {binary} appears to be in use (found: {', '.join(os.path.basename(f) for f in locked)})", file=sys.stderr)
        print("if this is a stale crash, remove those files and retry", file=sys.stderr)
        sys.exit(1)

    with _open_db(binary) as db:
        import ida_auto
        ida_auto.auto_wait()

        if skip_export:
            logger.info("skip-export mode, skipping export")
            try:
                serve(db, port, {}, shell_port=shell_port)
            finally:
                logger.info("done.")
        else:
            from .export import sync_exports
            sync_exports(db, export_dir)

            hooks = AutoSyncHooks(db, export_dir)
            hooks.hook()

            try:
                serve(db, port, {}, hooks=hooks, shell_port=shell_port)
            finally:
                hooks.flush_patches()
                hooks.unhook()
                logger.info("done.")


@app.command
def init() -> None:
    """Install SKILL.md and reference docs to ~/.claude/skills/ida-agent-bridge/."""
    import shutil
    import pathlib

    repo = pathlib.Path(__file__).parent.parent.parent.resolve()  # src/ida_bridge -> repo root
    target = (pathlib.Path.home() / ".claude" / "skills" / "ida-agent-bridge").resolve()

    if repo == target:
        print(f"already at {target}")
        return

    target.mkdir(parents=True, exist_ok=True)

    # SKILL.md
    shutil.copy2(repo / "SKILL.md", target / "SKILL.md")

    # reference/
    ref_src = repo / "reference"
    ref_dst = target / "reference"
    if ref_dst.exists():
        shutil.rmtree(ref_dst)
    shutil.copytree(ref_src, ref_dst)

    print(f"installed to {target}")


@app.command
def syms(
    binary: Annotated[str, cyclopts.Parameter(help="Binary file or .i64 database.")],
    output: Annotated[str, cyclopts.Parameter(help="Output symbols file (default: <name>.syms).")] = "",
) -> None:
    """Export function offset/name pairs, one per line, sorted by address."""
    if not output:
        output = os.path.join(os.getcwd(), f"{_strip_ext(binary)}.syms")

    with _open_db(binary) as db:
        import ida_auto
        ida_auto.auto_wait()

        from .export import export_symbols
        count = export_symbols(db, output)
        print(f"{count} symbols → {output}")


if __name__ == "__main__":
    app()

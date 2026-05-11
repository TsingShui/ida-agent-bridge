#!/usr/bin/env python3
"""ida-bridge — IDA Pro database export and real-time file sync.

Usage:
    ida-bridge <i64_path> <export_dir> [port]
"""
import sys
import os
import logging

import idapro  # noqa: F401 — initializes IDA Pro runtime

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger("ida_bridge")

DEFAULT_PORT = 13120
_KNOWN_EXTS = ('.i64', '.idb', '.so', '.dylib', '.dll', '.exe', '.elf', '.bin', '.out')


def _default_export_dir(binary_path: str) -> str:
    stem = os.path.basename(binary_path)
    for ext in _KNOWN_EXTS:
        if stem.endswith(ext):
            stem = stem[:-len(ext)]
            break
    return os.path.join(os.getcwd(), f'ida-bridge-{stem}')


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


def main() -> None:
    _check_update_async()

    if len(sys.argv) < 2:
        print(
            "Usage: ida-bridge <binary_or_i64> [export_dir] [port] [flags]\n"
            "\n"
            "Arguments:\n"
            "  binary_or_i64   binary file or .i64 database to open\n"
            "  export_dir      output directory (default: ./ida-bridge-<name>/)\n"
            "  port            REPL port (default: 13120)\n"
            "\n"
            "Flags:\n"
            "  --shell         enable interactive shell on port+1 (default: 13121)\n"
            "  --repl-only     skip all export and hooks, start REPL only\n"
            "\n"
            "Examples:\n"
            "  ida-bridge a.out\n"
            "  ida-bridge a.out /tmp/export 13200\n"
            "  ida-bridge a.out --shell\n"
            "  ida-bridge a.out --repl-only",
            file=sys.stderr,
        )
        sys.exit(1)

    idb_path = sys.argv[1]
    flags = [a for a in sys.argv[2:] if a.startswith('--')]
    args = [a for a in sys.argv[2:] if not a.startswith('--')]
    export_dir = args[0] if args else _default_export_dir(idb_path)
    port = int(args[1]) if len(args) > 1 else DEFAULT_PORT
    shell_port = DEFAULT_PORT + 1 if '--shell' in flags else None
    repl_only = '--repl-only' in flags

    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions
    from .hooks import AutoSyncHooks
    from .repl import serve

    import socket as _socket
    with _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM) as _s:
        if _s.connect_ex(("127.0.0.1", port)) == 0:
            print(f"error: port {port} already in use, another ida-bridge may be running", file=sys.stderr)
            sys.exit(1)

    base = os.path.splitext(idb_path)[0]
    locked = [f"{base}.{ext}" for ext in ("id0", "id1", "id2", "nam", "til")
              if os.path.isfile(f"{base}.{ext}")]
    if locked:
        print(f"error: {idb_path} appears to be in use (found: {', '.join(os.path.basename(f) for f in locked)})", file=sys.stderr)
        print("if this is a stale crash, remove those files and retry", file=sys.stderr)
        sys.exit(1)

    opts = IdaCommandOptions(auto_analysis=True)

    logger.info("opening %s...", idb_path)

    with Database.open(idb_path, opts) as db:
        import ida_auto
        ida_auto.auto_wait()


        if repl_only:
            logger.info("repl-only mode, skipping export")
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


if __name__ == "__main__":
    main()

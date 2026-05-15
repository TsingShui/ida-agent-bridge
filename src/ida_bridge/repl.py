import logging
import select
import signal
import socket
import threading
from typing import Any

from .command import exec_one, HELP
from .shell import ShellSession, handle_shell_line, make_shell_socket

logger = logging.getLogger(__name__)

DEFAULT_PORT = 13120
DEFAULT_SHELL_PORT = 13121
QUIT_CMD = "__QUIT__"


def serve(db, port: int, ns: dict[str, Any], hooks=None,
          shell_port: int | None = None) -> None:
    repl_srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    repl_srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    repl_srv.bind(("127.0.0.1", port))
    repl_srv.listen(1)
    logger.info("REPL ready — echo '!?' | nc localhost %d  for help", port)

    shell_srv = make_shell_socket(shell_port) if shell_port else None

    shutdown = threading.Event()

    def _signal_handler(sig, frame):
        if not shutdown.is_set():
            logger.info("received signal %s, shutting down...", sig)
            shutdown.set()
            try:
                repl_srv.close()
            except Exception:
                pass
            if shell_srv:
                try:
                    shell_srv.close()
                except Exception:
                    pass

    try:
        signal.signal(signal.SIGTERM, _signal_handler)
        signal.signal(signal.SIGINT, _signal_handler)
    except ValueError:
        # signal only works in the main thread; skip when running in a
        # background thread (e.g. during tests).
        pass

    ns.update({"db": db, "__builtins__": __builtins__})

    shell_session: ShellSession | None = None
    listen_socks = [repl_srv] + ([shell_srv] if shell_srv else [])

    try:
        while True:
            reads = list(listen_socks) + ([shell_session] if shell_session else [])
            try:
                readable, _, _ = select.select(reads, [], [], 1.0)
            except OSError:
                if shutdown.is_set():
                    break
                raise

            if shutdown.is_set():
                break

            for fd in readable:
                # 短连接：读完整输入、执行、断开
                if fd is repl_srv:
                    conn, _ = repl_srv.accept()
                    try:
                        chunks = []
                        while True:
                            chunk = conn.recv(65536)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        code = b"".join(chunks).decode()

                        if code.strip() == QUIT_CMD:
                            conn.sendall(b"stopped\n")
                            shutdown.set()
                            break

                        output, exit_code = exec_one(db, ns, code, hooks=hooks)
                        if output:
                            conn.sendall(output)
                        conn.sendall(f"\n__EXIT_{exit_code}__\n".encode())
                    finally:
                        conn.close()

                # shell：accept 新连接
                elif fd is shell_srv:
                    if shell_session:
                        shell_session.close()
                    conn, addr = shell_srv.accept()
                    shell_session = ShellSession(conn)
                    logger.info("shell connected")
                    shell_session.send(b"ida-bridge shell  (!? for help, exit to quit)\n")
                    shell_session.send_prompt()

                # shell：处理已连接 session 的输入
                elif shell_session and fd is shell_session:
                    line = shell_session.recv_line()
                    if line is None:
                        shell_session.close()
                        shell_session = None
                        logger.info("shell disconnected")
                    elif line != "":
                        alive = handle_shell_line(shell_session, db, ns, line, hooks=hooks)
                        if not alive:
                            shell_session.close()
                            shell_session = None
                            logger.info("shell disconnected")
    finally:
        if shell_session:
            shell_session.close()
        if shell_srv:
            try:
                shell_srv.close()
            except Exception:
                pass
        if not shutdown.is_set():
            repl_srv.close()
        logger.info("shutdown complete")

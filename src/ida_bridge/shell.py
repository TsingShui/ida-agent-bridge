import logging
import socket
from typing import Any

from .command import exec_one

logger = logging.getLogger(__name__)

PROMPT = b"> "
SHELL_QUIT_CMDS = {"exit", "quit", "q"}


class ShellSession:
    def __init__(self, conn: socket.socket):
        self.conn = conn
        self._buf = b""

    def fileno(self) -> int:
        return self.conn.fileno()

    def send_prompt(self):
        try:
            self.conn.sendall(PROMPT)
        except OSError:
            pass

    def recv_line(self) -> str | None:
        try:
            chunk = self.conn.recv(4096)
        except OSError:
            return None
        if not chunk:
            return None
        self._buf += chunk
        if b"\n" in self._buf:
            line, self._buf = self._buf.split(b"\n", 1)
            return line.rstrip(b"\r").decode(errors="replace")
        return ""

    def send(self, data: bytes):
        try:
            self.conn.sendall(data)
        except OSError:
            pass

    def close(self):
        try:
            self.conn.close()
        except OSError:
            pass


def handle_shell_line(session: ShellSession, db, ns: dict[str, Any],
                      line: str, hooks=None) -> bool:
    if line.strip().lower() in SHELL_QUIT_CMDS:
        session.send(b"bye\n")
        return False
    if not line.strip():
        session.send_prompt()
        return True
    output, _ = exec_one(db, ns, line, hooks=hooks)
    if output:
        session.send(output)
    session.send_prompt()
    return True


def make_shell_socket(port: int) -> socket.socket:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    logger.info("shell ready — rlwrap nc localhost %d", port)
    return srv

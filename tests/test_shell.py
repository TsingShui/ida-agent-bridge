import os
import shutil
import socket
import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SO = os.path.join(FIXTURES, "libssl.dylib")

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions
    import ida_auto

    d = tmp_path_factory.mktemp("shell")
    tmp_so = str(d / "libssl.dylib")
    shutil.copy2(SO, tmp_so)
    opts = IdaCommandOptions(auto_analysis=True, new_database=True)
    with Database.open(tmp_so, opts) as db:
        ida_auto.auto_wait()
        yield db


def _make_ns(db):
    return {"db": db, "__builtins__": __builtins__}


def _recv_all(sock: socket.socket, timeout: float = 5.0) -> bytes:
    """Read all available data from *sock* with a timeout.

    After handle_shell_line returns, data is already in the kernel buffer.
    We set a short timeout so recv returns what's available instead of
    blocking forever waiting for more data that will never come.
    """
    sock.settimeout(timeout)
    chunks = []
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
    except socket.timeout:
        pass
    return b"".join(chunks)


# ---------------------------------------------------------------------------
# handle_shell_line 单元行为
# ---------------------------------------------------------------------------

class TestHandleShellLine:
    """通过 socketpair 在进程内测试 handle_shell_line 的协议行为。"""

    def _make_session(self):
        from ida_bridge.shell import ShellSession
        a, b = socket.socketpair()
        session = ShellSession(a)
        # 给客户端端设超时，避免 recv 永远阻塞
        b.settimeout(2.0)
        return session, b  # b 是"客户端"端

    def test_empty_line_sends_prompt(self, db):
        from ida_bridge.shell import handle_shell_line
        session, client = self._make_session()
        try:
            alive = handle_shell_line(session, db, _make_ns(db), "")
            assert alive is True
            data = client.recv(4096)
            assert data == b"> "
        finally:
            session.close()
            client.close()

    def test_whitespace_only_sends_prompt(self, db):
        from ida_bridge.shell import handle_shell_line
        session, client = self._make_session()
        try:
            alive = handle_shell_line(session, db, _make_ns(db), "   ")
            assert alive is True
            data = client.recv(4096)
            assert data == b"> "
        finally:
            session.close()
            client.close()

    def test_exit_sends_bye(self, db):
        from ida_bridge.shell import handle_shell_line
        session, client = self._make_session()
        try:
            alive = handle_shell_line(session, db, _make_ns(db), "exit")
            assert alive is False
            data = client.recv(4096)
            assert b"bye" in data
        finally:
            session.close()
            client.close()

    def test_quit_sends_bye(self, db):
        from ida_bridge.shell import handle_shell_line
        session, client = self._make_session()
        try:
            alive = handle_shell_line(session, db, _make_ns(db), "quit")
            assert alive is False
            data = client.recv(4096)
            assert b"bye" in data
        finally:
            session.close()
            client.close()

    def test_q_sends_bye(self, db):
        from ida_bridge.shell import handle_shell_line
        session, client = self._make_session()
        try:
            alive = handle_shell_line(session, db, _make_ns(db), "q")
            assert alive is False
        finally:
            session.close()
            client.close()

    def test_command_returns_output_and_prompt(self, db):
        from ida_bridge.shell import handle_shell_line
        session, client = self._make_session()
        try:
            alive = handle_shell_line(session, db, _make_ns(db), "!?")
            assert alive is True
            # handle_shell_line 同步返回后数据已在 buffer，
            # 关闭 session 端让 client 读到 EOF
            session.close()
            data = _recv_all(client, timeout=2.0)
            assert b"!afl" in data
            assert data.endswith(b"> ")
        finally:
            client.close()


# ---------------------------------------------------------------------------
# ShellSession.recv_line 行为
# ---------------------------------------------------------------------------

class TestShellSessionRecvLine:
    def test_complete_line(self):
        from ida_bridge.shell import ShellSession
        a, b = socket.socketpair()
        session = ShellSession(a)
        try:
            b.sendall(b"!afl\n")
            line = session.recv_line()
            assert line == "!afl"
        finally:
            session.close()
            b.close()

    def test_crlf_stripped(self):
        from ida_bridge.shell import ShellSession
        a, b = socket.socketpair()
        session = ShellSession(a)
        try:
            b.sendall(b"!afl\r\n")
            line = session.recv_line()
            assert line == "!afl"
        finally:
            session.close()
            b.close()

    def test_partial_data_returns_empty(self):
        from ida_bridge.shell import ShellSession
        a, b = socket.socketpair()
        session = ShellSession(a)
        try:
            b.sendall(b"partial")  # 没有 \n
            line = session.recv_line()
            assert line == ""  # 数据不完整，返回空串等待更多数据
        finally:
            session.close()
            b.close()

    def test_connection_closed_returns_none(self):
        from ida_bridge.shell import ShellSession
        a, b = socket.socketpair()
        session = ShellSession(a)
        try:
            b.close()
            line = session.recv_line()
            assert line is None
        finally:
            session.close()


# ---------------------------------------------------------------------------
# make_shell_socket
# ---------------------------------------------------------------------------

class TestMakeShellSocket:
    def test_creates_listening_socket(self):
        from ida_bridge.shell import make_shell_socket
        srv = make_shell_socket(0)  # 让 OS 分配端口
        try:
            port = srv.getsockname()[1]
            assert port > 0
            # 能连上
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                client.connect(("127.0.0.1", port))
            finally:
                client.close()
        finally:
            srv.close()

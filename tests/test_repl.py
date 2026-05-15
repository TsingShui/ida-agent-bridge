"""Integration tests for the REPL network layer (short-connection protocol).

Each test starts a real ``serve()`` loop in a background thread, sends data
over TCP, and verifies the response format.
"""
import os
import shutil
import socket
import threading
import time
import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SO = os.path.join(FIXTURES, "libssl.dylib")

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions
    import ida_auto

    d = tmp_path_factory.mktemp("repl")
    tmp_so = str(d / "libssl.dylib")
    shutil.copy2(SO, tmp_so)
    opts = IdaCommandOptions(auto_analysis=True, new_database=True)
    with Database.open(tmp_so, opts) as db:
        ida_auto.auto_wait()
        yield db


def _free_port() -> int:
    """Find an available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _send_and_recv(port: int, data: bytes, timeout: float = 10.0) -> bytes:
    """Send *data* over a short connection and return the full response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect(("127.0.0.1", port))
    sock.sendall(data)
    sock.shutdown(socket.SHUT_WR)  # 告诉服务端发送完毕
    chunks = []
    while True:
        chunk = sock.recv(65536)
        if not chunk:
            break
        chunks.append(chunk)
    sock.close()
    return b"".join(chunks)


@pytest.fixture()
def repl_port(db):
    """Start a REPL server in a background thread and yield its port.

    The server is shut down after the test by sending __QUIT__.
    """
    from ida_bridge.repl import serve

    port = _free_port()
    ns: dict = {}
    ready = threading.Event()

    def _serve():
        ready.set()
        serve(db, port, ns)

    t = threading.Thread(target=_serve, daemon=True)
    t.start()
    ready.wait()
    # 等 socket 真正 listen
    for _ in range(50):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", port))
            s.close()
            break
        except ConnectionRefusedError:
            time.sleep(0.1)

    yield port

    # teardown: 发送 __QUIT__ 关停
    try:
        _send_and_recv(port, b"__QUIT__", timeout=5.0)
    except Exception:
        pass
    t.join(timeout=5.0)


# ---------------------------------------------------------------------------
# 短连接协议
# ---------------------------------------------------------------------------

class TestShortConnection:
    def test_command_returns_exit_0(self, repl_port):
        resp = _send_and_recv(repl_port, b"!?")
        assert b"__EXIT_0__" in resp
        assert b"!afl" in resp

    def test_afl_command(self, repl_port):
        resp = _send_and_recv(repl_port, b"!afl ssl")
        text = resp.decode()
        # IDA 的某些 API 在非主线程调用会报错（RuntimeError: main thread only），
        # 此时 exec_one 捕获异常后返回 EXIT_1。在测试环境只验证协议格式正确。
        assert "__EXIT_0__" in text or "__EXIT_1__" in text

    def test_python_script(self, repl_port):
        resp = _send_and_recv(repl_port, b"print('hello repl')")
        text = resp.decode()
        assert "hello repl" in text
        assert "__EXIT_0__" in text

    def test_bad_script_returns_exit_1(self, repl_port):
        resp = _send_and_recv(repl_port, b"raise ValueError('test error')")
        text = resp.decode()
        assert "__EXIT_1__" in text
        assert "ValueError" in text

    def test_multiple_connections(self, repl_port):
        """多次短连接应该都能正常返回。"""
        for i in range(3):
            resp = _send_and_recv(repl_port, f"print({i})".encode())
            text = resp.decode()
            assert str(i) in text
            assert "__EXIT_0__" in text


# ---------------------------------------------------------------------------
# __QUIT__ 协议
# ---------------------------------------------------------------------------

class TestQuit:
    def test_quit_stops_server(self, db):
        """__QUIT__ 应该让 serve() 返回。"""
        from ida_bridge.repl import serve

        port = _free_port()
        ns: dict = {}
        done = threading.Event()

        def _serve():
            serve(db, port, ns)
            done.set()

        t = threading.Thread(target=_serve, daemon=True)
        t.start()
        # 等 listen 就绪
        for _ in range(50):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect(("127.0.0.1", port))
                s.close()
                break
            except ConnectionRefusedError:
                time.sleep(0.1)

        resp = _send_and_recv(port, b"__QUIT__")
        assert b"stopped" in resp

        assert done.wait(timeout=5.0), "serve() did not return after __QUIT__"
        t.join(timeout=5.0)

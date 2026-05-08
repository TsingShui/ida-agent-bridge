import os
import tempfile
from ida_bridge.export import _write_func, _func_file


class TestFuncFile:
    def test_hex_address_filename(self):
        assert _func_file(0x1000) == "decompile/1000.c"

    def test_large_address(self):
        assert _func_file(0xABCDEF) == "decompile/ABCDEF.c"


class TestWriteFunc:
    def test_writes_file_with_header(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "decompile"))
            _write_func(d, 0x1000, "_add", "int _add() {}", [], [], None)
            path = os.path.join(d, "decompile", "1000.c")
            assert os.path.exists(path)
            content = open(path).read()
            assert "func-name: _add" in content
            assert "func-address: 0x1000" in content
            assert "int _add() {}" in content

    def test_fallback_reason_in_header(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "decompile"))
            _write_func(d, 0x2000, "_big", "void _big(){}", [], [], "too large")
            content = open(os.path.join(d, "decompile", "2000.c")).read()
            assert "fallback-reason: too large" in content

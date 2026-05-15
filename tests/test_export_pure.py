import os
import tempfile
from types import SimpleNamespace
from ida_bridge.export import _addr_list, _read_hash_index, _write_hash_index, _write_func, _write_index, parse_addrs


class TestAddrList:
    def test_empty(self):
        assert _addr_list([]) == "none"

    def test_single(self):
        f = SimpleNamespace(start_ea=0x1000)
        assert _addr_list([f]) == "0x1000"

    def test_multiple(self):
        funcs = [SimpleNamespace(start_ea=0x1000), SimpleNamespace(start_ea=0x2000)]
        result = _addr_list(funcs)
        assert result == "0x1000,0x2000"


class TestHashIndex:
    def test_missing_file(self):
        assert _read_hash_index("/nonexistent") == {}

    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            index = {0x1000: "abc123", 0x2000: "def456"}
            _write_hash_index(d, index)
            assert _read_hash_index(d) == index

    def test_empty(self):
        with tempfile.TemporaryDirectory() as d:
            _write_hash_index(d, {})
            assert _read_hash_index(d) == {}

    def test_sorted_keys(self):
        import json
        with tempfile.TemporaryDirectory() as d:
            index = {0x3000: "ccc", 0x1000: "aaa", 0x2000: "bbb"}
            _write_hash_index(d, index)
            with open(os.path.join(d, "hash_index.json")) as f:
                raw = json.load(f)
            assert list(raw.keys()) == ["1000", "2000", "3000"]


class TestWriteFuncWithHash:
    def test_func_hash_in_header(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "decompile"))
            _write_func(d, 0x1000, "foo", "void foo(){}", [], [], None, func_hash="deadbeef")
            with open(os.path.join(d, "decompile", "1000.c")) as fh:
                content = fh.read()
            assert "func-hash: deadbeef" in content

    def test_no_hash_kwarg_omits_line(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "decompile"))
            _write_func(d, 0x1000, "foo", "void foo(){}", [], [], None)
            with open(os.path.join(d, "decompile", "1000.c")) as fh:
                content = fh.read()
            assert "func-hash" not in content


class TestWriteIndex:
    def _make_row(self, ea, name):
        metrics = {
            "logic_lines": 5, "branch_density": 0.4, "call_density": 0.2,
            "string_density": 0.0, "opaque_density": 0.0,
            "total_insns": 10, "bitop_density": 0.1, "xor_density": 0.05,
        }
        callers = [SimpleNamespace(start_ea=0x9000)]
        callees = [SimpleNamespace(start_ea=0x8000)]
        return (ea, name, metrics, f"decompile/{ea:X}.c", callers, callees)

    def test_header_row(self):
        with tempfile.TemporaryDirectory() as d:
            _write_index(d, [self._make_row(0x1000, "foo")])
            with open(os.path.join(d, "function_index.tsv")) as fh:
                first = fh.readline().strip()
            columns = first.split("\t")
            assert columns[0] == "addr"
            for col in ("name", "logic_lines", "branch_density", "caller_count", "file", "callers", "callees"):
                assert col in columns

    def test_row_count(self):
        with tempfile.TemporaryDirectory() as d:
            rows = [self._make_row(0x1000, "foo"), self._make_row(0x2000, "bar")]
            _write_index(d, rows)
            lines = open(os.path.join(d, "function_index.tsv")).readlines()
            assert len(lines) == 3  # header + 2 rows

    def test_addr_hex_format(self):
        with tempfile.TemporaryDirectory() as d:
            _write_index(d, [self._make_row(0x1000, "foo")])
            lines = open(os.path.join(d, "function_index.tsv")).readlines()
            assert lines[1].startswith("0x1000\t")


class TestParseAddrs:
    def test_single(self):
        assert parse_addrs("0x1000") == [0x1000]

    def test_multiple(self):
        assert parse_addrs("0x1000,0x2000,0x3000") == [0x1000, 0x2000, 0x3000]

    def test_spaces(self):
        assert parse_addrs(" 0x1000 , 0x2000 ") == [0x1000, 0x2000]

    def test_empty_string(self):
        assert parse_addrs("") == []

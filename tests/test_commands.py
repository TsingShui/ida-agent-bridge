import os
import shutil
import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SO = os.path.join(FIXTURES, "libssl.dylib")

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions
    import ida_auto

    d = tmp_path_factory.mktemp("commands")
    tmp_so = str(d / "libssl.dylib")
    shutil.copy2(SO, tmp_so)
    opts = IdaCommandOptions(auto_analysis=True, new_database=True)
    with Database.open(tmp_so, opts) as db:
        ida_auto.auto_wait()
        yield db


def _dispatch(db, cmd_line: str) -> str:
    from ida_bridge.command import dispatch
    return dispatch(db, cmd_line)


def _known_func_ea(db):
    return next(db.functions.get_all()).start_ea


# ---------------------------------------------------------------------------
# resolve
# ---------------------------------------------------------------------------

class TestResolve:
    def test_hex_address(self, db):
        from ida_bridge.cmd import resolve
        ea = _known_func_ea(db)
        assert resolve(db, hex(ea)) == ea

    def test_known_symbol(self, db):
        from ida_bridge.cmd import resolve
        ea = resolve(db, "_BIO_f_ssl")
        assert isinstance(ea, int)
        assert ea != 0xFFFFFFFFFFFFFFFF

    def test_unknown_name_raises(self, db):
        from ida_bridge.cmd import resolve
        with pytest.raises(ValueError, match="name not found"):
            resolve(db, "__nonexistent_symbol_xyz__")


# ---------------------------------------------------------------------------
# !? / !help
# ---------------------------------------------------------------------------

class TestHelp:
    def test_help_contains_commands(self, db):
        result = _dispatch(db, "!?")
        for cmd in ("!afl", "!afi", "!axt", "!pdc", "!afn", "!hd", "!sb"):
            assert cmd in result

    def test_help_alias(self, db):
        assert _dispatch(db, "!help") == _dispatch(db, "!?")


# ---------------------------------------------------------------------------
# !afl
# ---------------------------------------------------------------------------

class TestAfl:
    def test_no_filter(self, db):
        result = _dispatch(db, "!afl")
        assert result != "(no results)"
        assert "0x" in result
        # 每行应该是 tab 分隔的
        lines = result.strip().splitlines()
        assert len(lines) > 100

    def test_filter_ssl(self, db):
        result = _dispatch(db, "!afl ssl")
        assert result != "(no results)"
        for line in result.splitlines():
            assert "ssl" in line.lower()

    def test_filter_no_match(self, db):
        result = _dispatch(db, "!afl zzz_nonexistent_zzz")
        assert result == "(no results)"


# ---------------------------------------------------------------------------
# !afi
# ---------------------------------------------------------------------------

class TestAfi:
    def test_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!afi").lower()

    def test_with_address(self, db):
        ea = _known_func_ea(db)
        result = _dispatch(db, f"!afi {hex(ea)}")
        assert "name:" in result
        assert "addr:" in result
        assert "size:" in result
        assert "callers:" in result
        assert "callees:" in result

    def test_with_symbol_name(self, db):
        result = _dispatch(db, "!afi _BIO_f_ssl")
        assert "name:" in result
        assert "_BIO_f_ssl" in result

    def test_invalid_address(self, db):
        result = _dispatch(db, "!afi 0x1")
        assert "no function" in result


# ---------------------------------------------------------------------------
# !iz
# ---------------------------------------------------------------------------

class TestIz:
    def test_no_filter(self, db):
        result = _dispatch(db, "!iz")
        assert result != "(no results)"
        assert "0x" in result

    def test_filter_ossltest(self, db):
        result = _dispatch(db, "!iz ossltest")
        assert "ossltest" in result.lower()

    def test_filter_no_match(self, db):
        result = _dispatch(db, "!iz zzz_nonexistent_zzz")
        assert result == "(no results)"


# ---------------------------------------------------------------------------
# !axi
# ---------------------------------------------------------------------------

class TestAxi:
    def test_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!axi").lower()

    def test_known_import(self, db):
        # 动态取一个真实存在的 import 名称
        imp = next(db.imports.get_all_imports(), None)
        assert imp is not None, "binary has no imports"
        result = _dispatch(db, f"!axi {imp.name}")
        # 应该有调用者，或者是 "(no callers for ...)"
        assert "0x" in result or "no callers" in result

    def test_unknown_import(self, db):
        result = _dispatch(db, "!axi __nonexistent_import__")
        assert "import not found" in result


# ---------------------------------------------------------------------------
# !axt / !axf
# ---------------------------------------------------------------------------

class TestXrefs:
    def test_axt_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!axt").lower()

    def test_axf_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!axf").lower()

    def test_axt_with_address(self, db):
        ea = _known_func_ea(db)
        result = _dispatch(db, f"!axt {hex(ea)}")
        assert isinstance(result, str)
        # 要么有结果(0x...)，要么 (no xrefs)
        assert "0x" in result or "no xrefs" in result

    def test_axf_with_address(self, db):
        ea = _known_func_ea(db)
        result = _dispatch(db, f"!axf {hex(ea)}")
        assert isinstance(result, str)

    def test_axt_with_symbol(self, db):
        result = _dispatch(db, "!axt _BIO_f_ssl")
        assert isinstance(result, str)


# ---------------------------------------------------------------------------
# !pd
# ---------------------------------------------------------------------------

class TestPd:
    def test_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!pd").lower()

    def test_default_count(self, db):
        ea = _known_func_ea(db)
        result = _dispatch(db, f"!pd {hex(ea)}")
        lines = result.strip().splitlines()
        assert len(lines) <= 16
        assert lines[0].startswith(f"0x{ea:x}")

    def test_custom_count(self, db):
        ea = _known_func_ea(db)
        result = _dispatch(db, f"!pd {hex(ea)} 4")
        lines = result.strip().splitlines()
        assert len(lines) <= 4


# ---------------------------------------------------------------------------
# !pdf
# ---------------------------------------------------------------------------

class TestPdf:
    def test_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!pdf").lower()

    def test_with_address(self, db):
        ea = _known_func_ea(db)
        result = _dispatch(db, f"!pdf {hex(ea)}")
        # 应包含 block 注释
        assert "; block" in result
        assert "0x" in result

    def test_with_symbol(self, db):
        result = _dispatch(db, "!pdf _BIO_f_ssl")
        assert "; block" in result

    def test_invalid_address(self, db):
        result = _dispatch(db, "!pdf 0x1")
        assert "no function" in result


# ---------------------------------------------------------------------------
# !pdc
# ---------------------------------------------------------------------------

class TestPdc:
    def test_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!pdc").lower()

    def test_contains_function_name(self, db):
        result = _dispatch(db, "!pdc _BIO_f_ssl")
        assert "_BIO_f_ssl" in result
        # 首行应是 "; <name> @ 0x..."
        assert result.startswith(";")

    def test_strip_vars_flag(self, db):
        full = _dispatch(db, "!pdc _BIO_f_ssl")
        stripped = _dispatch(db, "!pdc _BIO_f_ssl -s")
        # -s 版本应 <= full 版本的行数
        assert len(stripped.splitlines()) <= len(full.splitlines())

    def test_invalid_address(self, db):
        result = _dispatch(db, "!pdc 0x1")
        assert "no function" in result


# ---------------------------------------------------------------------------
# !mc
# ---------------------------------------------------------------------------

class TestMc:
    def test_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!mc").lower()

    def test_default_maturity(self, db):
        result = _dispatch(db, "!mc _BIO_f_ssl")
        assert result != "(no microcode)"

    def test_unknown_maturity(self, db):
        result = _dispatch(db, "!mc _BIO_f_ssl badlevel")
        assert "unknown maturity" in result
        assert "generated" in result  # 提示可选项

    def test_invalid_address(self, db):
        result = _dispatch(db, "!mc 0x1")
        assert "no function" in result


# ---------------------------------------------------------------------------
# !deps
# ---------------------------------------------------------------------------

class TestDeps:
    def test_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!deps").lower()

    def test_contains_root(self, db):
        ea = _known_func_ea(db)
        result = _dispatch(db, f"!deps {hex(ea)}")
        assert f"0x{ea:x}" in result

    def test_custom_depth(self, db):
        result = _dispatch(db, "!deps _DTLSv1_listen 1")
        # 深度 1：只展开第一层
        lines = result.strip().splitlines()
        assert lines[0].startswith("_DTLSv1_listen")
        # 子级缩进两个空格
        indented = [l for l in lines[1:] if l.startswith("  ") and not l.startswith("    ")]
        assert len(indented) > 0

    def test_invalid_address(self, db):
        result = _dispatch(db, "!deps 0x1")
        assert "no function" in result


# ---------------------------------------------------------------------------
# !cc / !ca
# ---------------------------------------------------------------------------

class TestComments:
    def test_cc_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!cc").lower()

    def test_ca_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!ca").lower()

    def test_cc_sets_comment(self, db):
        ea = _known_func_ea(db)
        result = _dispatch(db, f"!cc {hex(ea)} integration test comment")
        assert "comment set" in result

    def test_ca_sets_comment(self, db):
        ea = _known_func_ea(db)
        result = _dispatch(db, f"!ca {hex(ea)} addr level comment")
        assert "comment set" in result


# ---------------------------------------------------------------------------
# !afn
# ---------------------------------------------------------------------------

class TestAfn:
    def test_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!afn").lower()

    def test_rename_and_restore(self, db):
        from ida_bridge.cmd import resolve
        ea = resolve(db, "_SSL_CIPHER_get_name")
        result = _dispatch(db, f"!afn {hex(ea)} _test_renamed_cipher")
        assert "renamed" in result
        assert "_test_renamed_cipher" in result
        # 恢复原名
        restore = _dispatch(db, f"!afn {hex(ea)} _SSL_CIPHER_get_name")
        assert "renamed" in restore

    def test_invalid_address(self, db):
        result = _dispatch(db, "!afn 0x1 some_name")
        assert "no function" in result


# ---------------------------------------------------------------------------
# !hd
# ---------------------------------------------------------------------------

class TestHd:
    def test_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!hd").lower()

    def test_default_64_bytes(self, db):
        ea = _known_func_ea(db)
        result = _dispatch(db, f"!hd {hex(ea)}")
        lines = result.strip().splitlines()
        # 64 bytes / 16 per line = 4 lines
        assert len(lines) == 4
        # 每行以地址开头
        assert lines[0].startswith(f"0x{ea:x}")

    def test_custom_size(self, db):
        ea = _known_func_ea(db)
        result = _dispatch(db, f"!hd {hex(ea)} 32")
        lines = result.strip().splitlines()
        assert len(lines) == 2  # 32 / 16 = 2

    def test_with_symbol(self, db):
        result = _dispatch(db, "!hd _BIO_f_ssl")
        assert "0x" in result


# ---------------------------------------------------------------------------
# !sb
# ---------------------------------------------------------------------------

class TestSb:
    def test_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!sb").lower()

    def test_known_bytes(self, db):
        # 先从已知函数取前 4 字节作为搜索 pattern
        ea = _known_func_ea(db)
        import ida_bytes
        data = ida_bytes.get_bytes(ea, 4)
        hex_str = " ".join(f"{b:02x}" for b in data)
        result = _dispatch(db, f"!sb {hex_str}")
        assert "match" in result.lower()
        assert f"0x{ea:x}" in result

    def test_no_match(self, db):
        result = _dispatch(db, "!sb ff fe fd fc fb fa f9 f8 f7 f6 f5 f4 f3 f2 f1 f0")
        assert "no matches" in result.lower()


# ---------------------------------------------------------------------------
# !syms
# ---------------------------------------------------------------------------

class TestSyms:
    def test_missing_arg(self, db):
        assert "usage" in _dispatch(db, "!syms").lower()

    def test_export_symbols(self, db, tmp_path):
        out = str(tmp_path / "test.syms")
        result = _dispatch(db, f"!syms {out}")
        assert "exported" in result
        assert os.path.isfile(out)
        content = open(out).read()
        lines = content.strip().splitlines()
        assert len(lines) > 100
        # 每行格式：0x<offset> <name>
        first = lines[0].split()
        assert first[0].startswith("0x")
        assert len(first) == 2


# ---------------------------------------------------------------------------
# !pwd
# ---------------------------------------------------------------------------

class TestPwd:
    def test_returns_cwd(self, db):
        result = _dispatch(db, "!pwd")
        assert os.path.isdir(result.strip())


# ---------------------------------------------------------------------------
# unknown command
# ---------------------------------------------------------------------------

class TestUnknown:
    def test_unknown_command(self, db):
        result = _dispatch(db, "!notacommand")
        assert "unknown command" in result

    def test_case_insensitive(self, db):
        # 命令应不区分大小写
        result = _dispatch(db, "!AFL")
        assert result != "(no results)" or "unknown command" not in result


# ---------------------------------------------------------------------------
# exec_one — 通过 exec_one 走完整路径
# ---------------------------------------------------------------------------

class TestExecOne:
    def test_command_via_exec_one(self, db):
        from ida_bridge.command import exec_one
        output, code = exec_one(db, {"db": db, "__builtins__": __builtins__}, "!afl ssl")
        assert code == 0
        assert b"ssl" in output.lower()

    def test_python_script_via_exec_one(self, db):
        from ida_bridge.command import exec_one
        script = "print('hello from script')"
        output, code = exec_one(db, {"db": db, "__builtins__": __builtins__}, script)
        assert code == 0
        assert b"hello from script" in output

    def test_bad_script_returns_exit_1(self, db):
        from ida_bridge.command import exec_one
        output, code = exec_one(db, {"db": db, "__builtins__": __builtins__}, "raise RuntimeError('boom')")
        assert code == 1
        assert b"RuntimeError" in output
        assert b"boom" in output

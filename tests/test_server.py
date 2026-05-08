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

    d = tmp_path_factory.mktemp("server")
    tmp_so = str(d / "libssl.dylib")
    shutil.copy2(SO, tmp_so)
    opts = IdaCommandOptions(auto_analysis=True, new_database=True)
    with Database.open(tmp_so, opts) as db:
        ida_auto.auto_wait()
        yield db


def _known_func_ea(db):
    return next(db.functions.get_all()).start_ea


class TestResolve:
    def test_integer_string(self, db):
        from ida_bridge.cmd import resolve as _resolve
        ea = _known_func_ea(db)
        assert _resolve(db, hex(ea)) == ea

    def test_known_symbol(self, db):
        from ida_bridge.cmd import resolve as _resolve
        ea = _resolve(db, "_BIO_f_ssl")
        assert isinstance(ea, int)
        assert ea != 0xFFFFFFFFFFFFFFFF

    def test_unknown_name_raises(self, db):
        from ida_bridge.cmd import resolve as _resolve
        with pytest.raises(ValueError, match="name not found"):
            _resolve(db, "__nonexistent_symbol_xyz__")


class TestHelp:
    def test_help_contains_afl(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!?")
        assert "!afl" in result

    def test_help_alias(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!help")
        assert "!afl" in result


class TestAfl:
    def test_no_filter_lists_functions(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!afl")
        assert result != "(no results)"
        assert "0x" in result

    def test_ssl_filter(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!afl ssl")
        assert result != "(no results)", "!afl ssl returned no results"
        for line in result.splitlines():
            assert "ssl" in line.lower()


class TestAfi:
    def test_missing_arg_returns_usage(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!afi")
        assert "usage" in result.lower()

    def test_with_addr_returns_details(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        ea = _known_func_ea(db)
        result = _run_cmd(db, f"!afi {hex(ea)}")
        assert "name:" in result
        assert "callers:" in result
        assert "callees:" in result


class TestIz:
    def test_lists_strings(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!iz")
        assert result != "(no results)"

    def test_filter_ossltest(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!iz ossltest")
        assert "ossltest" in result.lower()


class TestAxtAxf:
    def test_axt_returns_result_or_no_xrefs(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        ea = _known_func_ea(db)
        result = _run_cmd(db, f"!axt {hex(ea)}")
        assert isinstance(result, str)

    def test_axf_returns_result_or_no_xrefs(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        ea = _known_func_ea(db)
        result = _run_cmd(db, f"!axf {hex(ea)}")
        assert isinstance(result, str)

    def test_axt_missing_arg(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!axt")
        assert "usage" in result.lower()


class TestPdc:
    def test_pseudocode_contains_function_name(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        from ida_bridge.cmd import resolve as _resolve
        ea = _resolve(db, "_BIO_f_ssl")
        result = _run_cmd(db, f"!pdc {hex(ea)}")
        assert "_BIO_f_ssl" in result

    def test_missing_arg(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!pdc")
        assert "usage" in result.lower()


class TestDeps:
    def test_contains_root_function(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        ea = _known_func_ea(db)
        result = _run_cmd(db, f"!deps {hex(ea)}")
        assert f"0x{ea:x}" in result

    def test_missing_arg(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!deps")
        assert "usage" in result.lower()


class TestCommentCommands:
    def test_cc_missing_arg(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!cc")
        assert "usage" in result.lower()

    def test_cc_sets_comment(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        ea = _known_func_ea(db)
        result = _run_cmd(db, f"!cc {hex(ea)} test_comment")
        assert "comment set" in result

    def test_ca_missing_arg(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!ca")
        assert "usage" in result.lower()

    def test_ca_sets_comment(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        ea = _known_func_ea(db)
        result = _run_cmd(db, f"!ca {hex(ea)} test_addr_comment")
        assert "comment set" in result


class TestAfn:
    def test_missing_arg(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!afn")
        assert "usage" in result.lower()

    def test_rename_succeeds(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        from ida_bridge.cmd import resolve as _resolve
        ea = _resolve(db, "_SSL_CIPHER_get_name")
        result = _run_cmd(db, f"!afn {hex(ea)} renamed_cipher_get_name")
        assert "renamed" in result
        # 恢复原名，避免污染 scope=module 的共享 db
        restore = _run_cmd(db, f"!afn {hex(ea)} _SSL_CIPHER_get_name")
        assert "renamed" in restore, f"teardown failed to restore symbol name: {restore}"


class TestUnknownCommand:
    def test_unknown_returns_error(self, db):
        from ida_bridge.repl import _dispatch as _run_cmd
        result = _run_cmd(db, "!notacommand")
        assert "unknown command" in result

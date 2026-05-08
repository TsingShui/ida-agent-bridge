import os
import shutil
import time
import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SO = os.path.join(FIXTURES, "libssl.dylib")

pytestmark = pytest.mark.integration


def _open_fresh(tmp_path_factory, label):
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions
    import ida_auto

    d = tmp_path_factory.mktemp(label)
    tmp_so = str(d / "libssl.dylib")
    shutil.copy2(SO, tmp_so)
    opts = IdaCommandOptions(auto_analysis=True, new_database=True)
    db = Database.open(tmp_so, opts)
    try:
        ida_auto.auto_wait()
    except Exception:
        db.close()
        raise
    return d, db


class TestIncremental:
    def test_incremental_refresh_updates_mtime(self, tmp_path_factory):
        from ida_bridge.export import export_all, export_incremental

        d, db = _open_fresh(tmp_path_factory, "incr")
        try:
            out = str(d / "out")
            export_all(db, out)

            funcs = list(db.functions.get_all())
            ea = funcs[0].start_ea
            addr_hex = f"{ea:X}"
            path = os.path.join(out, f"decompile/{addr_hex}.c")

            mtime_before = os.path.getmtime(path)
            time.sleep(0.05)
            export_incremental(db, out, [ea])
            mtime_after = os.path.getmtime(path)

            assert mtime_after > mtime_before
        finally:
            db.close()


class TestStringPatch:
    def test_string_content_changes_after_patch(self, tmp_path_factory):
        d, db = _open_fresh(tmp_path_factory, "patch")
        try:
            target = None
            for s in db.strings.get_all():
                if "ossltest" in str(s):
                    target = s
                    break
            assert target is not None, "target string 'ossltest' not found"

            original = str(target)
            ea = target.address
            db.bytes.patch_byte_at(ea, ord('X'))

            updated = next(
                (str(s) for s in db.strings.get_all() if s.address == ea),
                None
            )
            assert updated is not None
            assert updated != original
            assert updated.startswith('X'), f"expected patched string to start with 'X', got: {updated!r}"
        finally:
            db.close()

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


class TestHooksFuncDeleted:
    def test_func_deleted_removes_file(self, tmp_path_factory):
        from ida_bridge.export import export_all
        from ida_bridge.hooks import AutoSyncHooks

        d, db = _open_fresh(tmp_path_factory, "del")
        try:
            out = str(d / "out")
            export_all(db, out)

            funcs = list(db.functions.get_all())
            func = funcs[0]
            ea = func.start_ea
            addr_hex = f"{ea:X}"
            path = os.path.join(out, f"decompile/{addr_hex}.c")
            assert os.path.exists(path)

            hooks = AutoSyncHooks(db, out)
            hooks.func_deleted(ea)
            hooks.flush_patches()

            assert not os.path.exists(path)
        finally:
            db.close()


class TestHooksFuncUpdated:
    def test_func_updated_refreshes_file(self, tmp_path_factory):
        from ida_bridge.export import export_all
        from ida_bridge.hooks import AutoSyncHooks

        d, db = _open_fresh(tmp_path_factory, "upd")
        try:
            out = str(d / "out")
            export_all(db, out)

            funcs = list(db.functions.get_all())
            func = funcs[0]
            ea = func.start_ea
            addr_hex = f"{ea:X}"
            path = os.path.join(out, f"decompile/{addr_hex}.c")
            assert os.path.exists(path), f"expected {path} to exist after export_all"
            mtime_before = os.path.getmtime(path)

            time.sleep(0.05)
            hooks = AutoSyncHooks(db, out)
            hooks.func_updated(func)
            hooks.flush_patches()

            assert os.path.getmtime(path) > mtime_before
        finally:
            db.close()


class TestHooksRenamed:
    def test_renamed_refreshes_file(self, tmp_path_factory):
        from ida_bridge.export import export_all
        from ida_bridge.hooks import AutoSyncHooks

        d, db = _open_fresh(tmp_path_factory, "ren")
        try:
            out = str(d / "out")
            export_all(db, out)

            funcs = list(db.functions.get_all())
            func = funcs[0]
            ea = func.start_ea
            addr_hex = f"{ea:X}"
            path = os.path.join(out, f"decompile/{addr_hex}.c")
            assert os.path.exists(path), f"expected {path} to exist after export_all"
            mtime_before = os.path.getmtime(path)

            time.sleep(0.05)
            hooks = AutoSyncHooks(db, out)
            hooks.renamed(ea, "new_name_test")
            hooks.flush_patches()

            assert os.path.getmtime(path) > mtime_before
        finally:
            db.close()


class TestHooksBytePatch:
    def test_byte_patched_sets_pending(self, tmp_path_factory):
        from ida_bridge.hooks import AutoSyncHooks

        d, db = _open_fresh(tmp_path_factory, "bpatch")
        try:
            hooks = AutoSyncHooks(db, str(d / "out"))
            assert not hooks.patch_pending
            hooks.byte_patched(0x1000, 0)
            assert hooks.patch_pending
        finally:
            db.close()

    def test_flush_patches_clears_pending(self, tmp_path_factory):
        from ida_bridge.export import export_all
        from ida_bridge.hooks import AutoSyncHooks
        import time

        d, db = _open_fresh(tmp_path_factory, "flush")
        try:
            out = str(d / "out")
            export_all(db, out)

            funcs = list(db.functions.get_all())
            func = funcs[0]
            ea = func.start_ea
            addr_hex = f"{ea:X}"
            path = os.path.join(out, f"decompile/{addr_hex}.c")
            assert os.path.exists(path)
            mtime_before = os.path.getmtime(path)

            hooks = AutoSyncHooks(db, out)
            hooks.byte_patched(ea, 0)
            assert hooks.patch_pending

            time.sleep(0.05)
            hooks.flush_patches()
            assert not hooks.patch_pending
            assert os.path.getmtime(path) > mtime_before
        finally:
            db.close()

    def test_byte_patch_in_data_segment_sets_strings_dirty(self, tmp_path_factory):
        from ida_bridge.hooks import AutoSyncHooks, _build_data_ranges

        d, db = _open_fresh(tmp_path_factory, "dirty")
        try:
            hooks = AutoSyncHooks(db, str(d / "out"))
            ranges = _build_data_ranges(db)
            if not ranges:
                pytest.skip("no DATA segments in this binary")

            start_ea = ranges[0][0]
            hooks.byte_patched(start_ea, 0)
            assert hooks._strings_dirty
        finally:
            db.close()


class TestHooksFrameUdmRenamed:
    def test_frame_udm_renamed_refreshes_file(self, tmp_path_factory):
        from ida_bridge.export import export_all
        from ida_bridge.hooks import AutoSyncHooks

        d, db = _open_fresh(tmp_path_factory, "udm")
        try:
            out = str(d / "out")
            export_all(db, out)

            funcs = list(db.functions.get_all())
            func = funcs[0]
            ea = func.start_ea
            addr_hex = f"{ea:X}"
            path = os.path.join(out, f"decompile/{addr_hex}.c")
            assert os.path.exists(path), f"expected {path} to exist after export_all"
            mtime_before = os.path.getmtime(path)

            time.sleep(0.05)
            hooks = AutoSyncHooks(db, out)
            hooks.frame_udm_renamed(ea, None, "old_var")
            hooks.flush_patches()

            assert os.path.getmtime(path) > mtime_before
        finally:
            db.close()

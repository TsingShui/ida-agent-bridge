import bisect
import os
import logging
from ida_domain.hooks import DatabaseHooks
from .export import export_incremental, export_strings, _patch_index, _func_file

logger = logging.getLogger(__name__)

_DATA_CLASSES = {'DATA', 'CONST'}


def _build_data_ranges(db) -> list[tuple[int, int]]:
    import ida_segment
    return sorted(
        (seg.start_ea, seg.end_ea)
        for seg in db.segments
        if ida_segment.get_segm_class(seg) in _DATA_CLASSES
    )


def _ea_in_ranges(ea: int, ranges: list[tuple[int, int]]) -> bool:
    starts = [r[0] for r in ranges]
    idx = bisect.bisect_right(starts, ea) - 1
    if idx >= 0:
        start, end = ranges[idx]
        if start <= ea < end:
            return True
    return False


class AutoSyncHooks(DatabaseHooks):
    def __init__(self, db, export_dir: str):
        super().__init__()
        self._db = db
        self._export_dir = export_dir
        self._dirty_eas: set[int] = set()
        self._dirty_reasons: dict[int, str] = {}
        self._deleted_eas: set[int] = set()
        self._strings_dirty: bool = False
        self._data_ranges = _build_data_ranges(db)

    @property
    def patch_pending(self) -> bool:
        return bool(self._dirty_eas or self._deleted_eas or self._strings_dirty)

    def _mark(self, ea: int, reason: str = ""):
        if ea not in self._dirty_eas:
            self._dirty_reasons[ea] = reason
        self._dirty_eas.add(ea)

    def flush_patches(self):
        if not self.patch_pending:
            return

        dirty_eas = self._dirty_eas
        dirty_reasons = self._dirty_reasons
        deleted_eas = self._deleted_eas
        strings_dirty = self._strings_dirty
        self._dirty_eas = set()
        self._dirty_reasons = {}
        self._deleted_eas = set()
        self._strings_dirty = False

        try:
            # 解析 ea → func start_ea（跳过已删函数）
            func_eas: dict[int, str] = {}
            for ea in dirty_eas:
                func = self._db.functions.get_at(ea)
                if func and func.start_ea not in deleted_eas:
                    if func.start_ea not in func_eas:
                        func_eas[func.start_ea] = dirty_reasons.get(ea, "")

            if func_eas:
                export_incremental(self._db, self._export_dir, func_eas)

            if deleted_eas:
                for ea in deleted_eas:
                    path = os.path.join(self._export_dir, _func_file(ea))
                    if os.path.exists(path):
                        os.remove(path)
                _patch_index(self._export_dir, [], remove_eas=deleted_eas)

            if strings_dirty:
                export_strings(self._db, self._export_dir)
        except Exception as e:
            logger.error("flush error: %s", e)

    def renamed(self, ea, new_name, local_name=False, old_name=None):
        logger.debug("renamed %#x: %s → %s", ea, old_name, new_name)
        self._mark(ea, f"renamed:{old_name}→{new_name}")
        func = self._db.functions.get_at(ea)
        if func:
            for caller in self._db.functions.get_callers(func):
                self._mark(caller.start_ea, f"callee renamed:{new_name}")
        return 0

    def func_added(self, pfn):
        logger.debug("func_added %#x", pfn.start_ea)
        self._mark(pfn.start_ea, "func_added")
        return 0

    def func_deleted(self, func_ea):
        logger.debug("func_deleted %#x", func_ea)
        self._deleted_eas.add(func_ea)
        self._dirty_eas.discard(func_ea)
        return 0

    def func_updated(self, pfn):
        logger.debug("func_updated %#x", pfn.start_ea)
        self._mark(pfn.start_ea, "func_updated")
        return 0

    def cmt_changed(self, ea, repeatable_cmt):
        logger.debug("cmt_changed %#x", ea)
        self._mark(ea, "cmt_changed")
        return 0

    def range_cmt_changed(self, kind, a, cmt, repeatable):
        import ida_range
        if kind == ida_range.RANGE_KIND_FUNC:
            logger.debug("func_cmt_changed %#x", a.start_ea)
            self._mark(a.start_ea, "cmt_changed")
        return 0

    def extra_cmt_changed(self, ea, line_idx, cmt):
        self._mark(ea, "cmt_changed")
        return 0

    def byte_patched(self, ea, old_value):
        self._mark(ea, "byte_patched")
        if not self._strings_dirty and _ea_in_ranges(ea, self._data_ranges):
            self._strings_dirty = True
        return 0

    def ti_changed(self, ea, type, fnames):
        self._mark(ea, "ti_changed")
        return 0

    def frame_udm_renamed(self, func_ea, udm, oldname):
        self._mark(func_ea, "frame_udm_renamed")
        return 0

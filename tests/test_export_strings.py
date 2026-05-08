import os
import shutil
import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")
SO = os.path.join(FIXTURES, "libssl.dylib")

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def export_dir(tmp_path_factory):
    from ida_domain import Database
    from ida_domain.database import IdaCommandOptions
    import ida_auto
    from ida_bridge.export import export_all

    d = tmp_path_factory.mktemp("strings")
    tmp_so = str(d / "libssl.dylib")
    shutil.copy2(SO, tmp_so)
    out = str(d / "out")
    opts = IdaCommandOptions(auto_analysis=True, new_database=True)
    with Database.open(tmp_so, opts) as db:
        ida_auto.auto_wait()
        export_all(db, out)
    yield out


class TestStrings:
    def test_header(self, export_dir):
        with open(os.path.join(export_dir, "strings.tsv")) as fh:
            first_line = fh.readline().strip()
        assert first_line == "addr\tencoding\tcontents"

    def test_ossltest_present(self, export_dir):
        with open(os.path.join(export_dir, "strings.tsv")) as fh:
            content = fh.read()
        assert "ossltest" in content

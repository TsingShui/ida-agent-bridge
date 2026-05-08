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

    d = tmp_path_factory.mktemp("structure")
    tmp_so = str(d / "libssl.dylib")
    shutil.copy2(SO, tmp_so)
    out = str(d / "out")
    opts = IdaCommandOptions(auto_analysis=True, new_database=True)
    with Database.open(tmp_so, opts) as db:
        ida_auto.auto_wait()
        export_all(db, out)
        yield out


class TestExportStructure:
    def test_decompile_dir_exists(self, export_dir):
        assert os.path.isdir(os.path.join(export_dir, "decompile"))

    def test_function_index_exists(self, export_dir):
        assert os.path.isfile(os.path.join(export_dir, "function_index.tsv"))

    def test_strings_tsv_exists(self, export_dir):
        assert os.path.isfile(os.path.join(export_dir, "strings.tsv"))

    def test_imports_tsv_exists(self, export_dir):
        assert os.path.isfile(os.path.join(export_dir, "imports.tsv"))

    def test_exports_tsv_exists(self, export_dir):
        assert os.path.isfile(os.path.join(export_dir, "exports.tsv"))

    def test_imports_contains_crypto_malloc(self, export_dir):
        with open(os.path.join(export_dir, "imports.tsv")) as fh:
            content = fh.read()
        assert "CRYPTO_malloc" in content

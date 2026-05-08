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

    d = tmp_path_factory.mktemp("functions")
    tmp_so = str(d / "libssl.dylib")
    shutil.copy2(SO, tmp_so)
    out = str(d / "out")
    opts = IdaCommandOptions(auto_analysis=True, new_database=True)
    with Database.open(tmp_so, opts) as db:
        ida_auto.auto_wait()
        export_all(db, out)
        yield out


def _read_index(export_dir):
    path = os.path.join(export_dir, "function_index.tsv")
    rows = {}
    with open(path) as fh:
        lines = fh.readlines()
    headers = lines[0].strip().split("\t")
    for line in lines[1:]:
        parts = line.strip().split("\t")
        row = dict(zip(headers, parts))
        rows[row["name"]] = row
    return rows


class TestFunctionFiles:
    def test_at_least_100_c_files(self, export_dir):
        c_files = [f for f in os.listdir(os.path.join(export_dir, "decompile")) if f.endswith(".c")]
        assert len(c_files) >= 100

    def test_bio_f_ssl_file_exists(self, export_dir):
        rows = _read_index(export_dir)
        assert "_BIO_f_ssl" in rows
        addr_hex = rows["_BIO_f_ssl"]["addr"][2:].upper()
        assert os.path.isfile(os.path.join(export_dir, f"decompile/{addr_hex}.c"))

    def test_pseudocode_header_fields(self, export_dir):
        rows = _read_index(export_dir)
        addr_hex = rows["_BIO_f_ssl"]["addr"][2:].upper()
        with open(os.path.join(export_dir, f"decompile/{addr_hex}.c")) as fh:
            content = fh.read()
        assert "func-name:" in content
        assert "func-address:" in content
        assert "callers:" in content
        assert "callees:" in content

    def test_pseudocode_contains_function_name(self, export_dir):
        rows = _read_index(export_dir)
        addr_hex = rows["_BIO_f_ssl"]["addr"][2:].upper()
        with open(os.path.join(export_dir, f"decompile/{addr_hex}.c")) as fh:
            content = fh.read()
        assert "_BIO_f_ssl" in content

    def test_dtls_listen_has_callees(self, export_dir):
        rows = _read_index(export_dir)
        assert "_DTLSv1_listen" in rows
        callees_val = rows["_DTLSv1_listen"].get("callees", "none")
        assert callees_val != "none", f"_DTLSv1_listen has no callees, got: {callees_val!r}"


class TestFunctionIndex:
    def test_known_functions_in_index(self, export_dir):
        rows = _read_index(export_dir)
        for name in ("_BIO_f_ssl", "_SSL_CIPHER_get_name", "_DTLSv1_listen", "_OPENSSL_init_ssl"):
            assert name in rows

    def test_bio_f_ssl_has_insns(self, export_dir):
        rows = _read_index(export_dir)
        assert int(rows["_BIO_f_ssl"]["total_insns"]) > 0

    def test_dtls_listen_branch_density_parseable(self, export_dir):
        rows = _read_index(export_dir)
        assert float(rows["_DTLSv1_listen"]["branch_density"]) >= 0

    def test_openssl_init_caller_count_parseable(self, export_dir):
        rows = _read_index(export_dir)
        assert int(rows["_OPENSSL_init_ssl"]["caller_count"]) >= 0

    def test_at_least_one_row_has_positive_metrics(self, export_dir):
        rows = _read_index(export_dir)
        assert any(
            int(row.get("logic_lines", 0)) > 0 and int(row.get("total_insns", 0)) > 0
            for row in rows.values()
            if row.get("logic_lines", "").isdigit() and row.get("total_insns", "").isdigit()
        )

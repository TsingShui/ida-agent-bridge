from unittest.mock import patch
from ida_bridge.cli import _default_export_dir


class TestDefaultExportDir:
    def test_i64_extension_stripped(self):
        with patch('os.getcwd', return_value='/work'):
            assert _default_export_dir('/path/to/target.i64') == '/work/ida-bridge-target'

    def test_so_extension_stripped(self):
        with patch('os.getcwd', return_value='/work'):
            assert _default_export_dir('/path/to/target.so') == '/work/ida-bridge-target'

    def test_dylib_extension_stripped(self):
        with patch('os.getcwd', return_value='/work'):
            assert _default_export_dir('/path/to/libtarget.dylib') == '/work/ida-bridge-libtarget'

    def test_unknown_extension_kept(self):
        with patch('os.getcwd', return_value='/work'):
            assert _default_export_dir('/path/to/target.apk') == '/work/ida-bridge-target.apk'

    def test_basename_only(self):
        with patch('os.getcwd', return_value='/work'):
            assert _default_export_dir('target.so') == '/work/ida-bridge-target'

    def test_uses_cwd(self):
        with patch('os.getcwd', return_value='/my/project'):
            result = _default_export_dir('foo.so')
            assert result.startswith('/my/project/')

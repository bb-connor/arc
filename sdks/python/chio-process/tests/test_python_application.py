import os
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from chio_process.python_application import package_modules


class PythonApplicationTests(unittest.TestCase):
    def test_captured_sibling_imports_need_no_source_directory(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            main, sibling = root / "main.py", root / "sibling.py"
            main.write_text("from sibling import VALUE\nprint(VALUE)\n")
            sibling.write_text("VALUE = 'captured'\n")
            main.chmod(0o600)
            sibling.chmod(0o600)
            archive = package_modules(root / "app.zip", {"main.py": main, "sibling.py": sibling})
            main.unlink()
            sibling.write_text("raise RuntimeError('ambient source was used')\n")
            result = subprocess.check_output(
                [
                    sys.executable,
                    "-I",
                    "-B",
                    "-c",
                    f"import sys,runpy;sys.path.insert(0,{str(archive)!r});"
                    "runpy.run_module('main',run_name='__main__')",
                ],
                cwd=root,
            )
            self.assertEqual(result, b"captured\n")
            with zipfile.ZipFile(archive) as contents:
                self.assertEqual(set(contents.namelist()), {"main.py", "sibling.py"})
            self.assertEqual(os.stat(archive).st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                package_modules(archive, {"sibling.py": sibling})

    def test_alias_and_writable_source_are_refused(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            source = root / "main.py"
            source.write_text("print('original')\n")
            alias = root / "alias.py"
            alias.symlink_to(source)
            with self.assertRaises(OSError):
                package_modules(root / "alias.zip", {"main.py": alias})
            source.chmod(0o666)
            with self.assertRaises(ValueError):
                package_modules(root / "writable.zip", {"main.py": source})
            source.chmod(0o600)
            for name in ("../main.py", "/main.py", "a/../main.py", "./main.py", "main.txt"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    package_modules(root / "escape.zip", {name: source})


if __name__ == "__main__":
    unittest.main()

"""Evidence must describe the executable used for every installed profile."""

import hashlib
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import qualify


class ExecutableSnapshotTests(unittest.TestCase):
    def test_source_replacement_cannot_change_the_qualified_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "chio"
            original = b"#!/bin/sh\nprintf 'first\\n'\n"
            source.write_bytes(original)
            source.chmod(0o755)
            output = root / "evidence"
            output.mkdir()

            binary = qualify.snapshot_executable(source, output)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o755)
            replacement = root / "replacement"
            replacement.write_text("#!/bin/sh\nprintf 'replacement\\n'\n")
            replacement.chmod(0o755)
            replacement.replace(source)

            result = subprocess.run([binary], check=True, capture_output=True, text=True)
            self.assertEqual(result.stdout, "first\n")
            self.assertEqual(binary, output / "bin" / "chio")
            self.assertFalse(binary.is_symlink())
            self.assertEqual(stat.S_IMODE(binary.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(binary.stat().st_mode), 0o700)
            with binary.open("rb") as stream:
                self.assertEqual(
                    hashlib.file_digest(stream, "sha256").digest(),
                    hashlib.sha256(original).digest(),
                )

    def test_existing_snapshot_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "chio"
            source.write_bytes(b"replacement")
            source.chmod(0o700)
            output = root / "evidence"
            destination = output / "bin"
            destination.mkdir(parents=True)
            sentinel = destination / "chio"
            sentinel.write_bytes(b"retained evidence")

            with self.assertRaises(FileExistsError):
                qualify.snapshot_executable(source, output)

            self.assertEqual(sentinel.read_bytes(), b"retained evidence")


if __name__ == "__main__":
    unittest.main()

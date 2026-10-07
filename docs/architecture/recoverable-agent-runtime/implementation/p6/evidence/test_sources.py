"""Source archives must preserve every byte, identity and complete inventory."""
import hashlib
import importlib
import io
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from package_sources import audit_archive


class SourceArchiveTest(unittest.TestCase):
    def test_sealed_inventory_matches_verifiers_string_order_with_prefix_directories(self):
        sealer = importlib.import_module("seal-package")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            expected = ["evidence/final-linux-postfix/native.log",
                        "evidence/final-linux/native.log", "verification.json"]
            for relative in expected + ["package-integrity.json", "__pycache__/cache.pyc"]:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b"retained artifact")
            with patch.object(sealer, "PHASE", root):
                observed = [str(path.relative_to(root)) for path in sealer.artifact_paths()]
            self.assertEqual(observed, expected)

    def test_changed_missing_duplicate_extra_and_link_members_refuse(self):
        content = b"actual source\n"
        expected = [{"path": "crate/src.rs", "sha256": hashlib.sha256(content).hexdigest()}]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sources.tar.gz"
            for mutation in [None, "changed", "missing", "duplicate", "extra", "link"]:
                with tarfile.open(path, "w:gz") as archive:
                    if mutation != "missing":
                        entry = tarfile.TarInfo("crate/src.rs")
                        payload = b"altered source\n" if mutation == "changed" else content
                        if mutation == "link":
                            entry.type = tarfile.SYMTYPE
                            entry.linkname = "outside"
                        else:
                            entry.size = len(payload)
                        archive.addfile(entry, io.BytesIO(payload))
                        if mutation == "duplicate":
                            archive.addfile(entry, io.BytesIO(payload))
                    if mutation == "extra":
                        entry = tarfile.TarInfo("undeclared.rs")
                        entry.size = len(content)
                        archive.addfile(entry, io.BytesIO(content))
                if mutation is None:
                    self.assertEqual(audit_archive(path, expected), 1)
                else:
                    with self.assertRaises(ValueError, msg=mutation):
                        audit_archive(path, expected)


if __name__ == "__main__":
    unittest.main()

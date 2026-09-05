#!/usr/bin/env python3
"""Reject malformed runtime archives before they can run tool processes."""

import copy
import io
import json
from pathlib import Path
import runpy
import tarfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1]
RUNTIME = runpy.run_path(str(SCRIPTS / "check-agent-preview-runtime.py"))
FIXTURES = runpy.run_path(str(SCRIPTS / "tests/package-agent-preview.test.py"))


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = FIXTURES["PreviewTests"]("test_archive_bytes_are_reproducible")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.archive = self.fixture.output
        RUNTIME["PACKAGING"]["package"](self.fixture.installation, self.archive)
        self.destination = self.root / "extracted"

    def extract(self, archive=None):
        archive = archive or self.archive
        return RUNTIME["extract_preview"](archive, RUNTIME["digest"](archive), self.destination)

    def rewrite(self, transform):
        replacement = self.root / "changed.tar.gz"
        with tarfile.open(self.archive) as source, tarfile.open(replacement, "w:gz") as output:
            for original in source.getmembers():
                entry = copy.copy(original)
                data = source.extractfile(original).read()
                entries = transform(entry, data)
                for item, contents in entries:
                    if item.isfile():
                        item.size = len(contents)
                    output.addfile(item, io.BytesIO(contents) if item.isfile() else None)
        return replacement

    def test_valid_archive_extracts_with_verified_inventory(self):
        manifest = self.extract()
        files = {str(path.relative_to(self.destination)) for path in self.destination.rglob("*") if path.is_file()}
        self.assertEqual(files, RUNTIME["inventory"](manifest))
        self.assertEqual(manifest["source_revision"], "a" * 40)

    def test_wrong_archive_hash_never_extracts(self):
        with self.assertRaisesRegex(ValueError, "archive checksum"):
            RUNTIME["extract_preview"](self.archive, "0" * 64, self.destination)
        self.assertFalse(self.destination.exists())

    def test_duplicate_members_are_rejected_before_extraction(self):
        changed = self.rewrite(lambda entry, data: [(entry, data), (entry, data)] if entry.name == "README.md" else [(entry, data)])
        with self.assertRaises(ValueError):
            self.extract(changed)
        self.assertFalse(self.destination.exists())

    def test_unsafe_and_unlisted_paths_are_rejected_before_extraction(self):
        for name in ("../escaped", "/absolute", "python//unexpected", "generated/signing.seed"):
            with self.subTest(name=name):
                def transform(entry, data):
                    if entry.name == "README.md":
                        entry.name = name
                    return [(entry, data)]
                with self.assertRaises(ValueError):
                    self.extract(self.rewrite(transform))
                self.assertFalse(self.destination.exists())
                self.assertFalse((self.root / "escaped").exists())

    def test_links_and_special_files_are_rejected_before_extraction(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with self.subTest(kind=kind):
                def transform(entry, data):
                    if entry.name == "README.md":
                        entry.type = kind
                        entry.linkname = "../outside"
                    return [(entry, data)]
                with self.assertRaises(ValueError):
                    self.extract(self.rewrite(transform))
                self.assertFalse(self.destination.exists())

    def test_changed_payload_fails_checksum_verification(self):
        changed = self.rewrite(lambda entry, data: [(entry, data + b"tampered" if entry.name == "bin/chio" else data)])
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            self.extract(changed)

    def test_incomplete_manifest_inventory_is_rejected(self):
        def transform(entry, data):
            if entry.name == "PREVIEW.json":
                manifest = json.loads(data)
                del manifest["sha256"]["bin/chio"]
                data = json.dumps(manifest).encode()
            return [(entry, data)]
        with self.assertRaisesRegex(ValueError, "incomplete preview checksums"):
            self.extract(self.rewrite(transform))
        self.assertFalse(self.destination.exists())

    def test_oversized_metadata_is_rejected_before_extraction(self):
        changed = self.rewrite(lambda entry, data: [(entry, b"x" * (RUNTIME["MAX_METADATA"] + 1) if entry.name == "PREVIEW.json" else data)])
        with self.assertRaisesRegex(ValueError, "metadata exceeds"):
            self.extract(changed)
        self.assertFalse(self.destination.exists())

    def test_unexpected_file_permissions_are_rejected(self):
        def transform(entry, data):
            if entry.name == "bin/chio":
                entry.mode = 0o777
            return [(entry, data)]
        with self.assertRaises(ValueError):
            self.extract(self.rewrite(transform))
        self.assertFalse(self.destination.exists())

    def test_invalid_host_inputs_never_start_docker(self):
        with patch.object(RUNTIME["subprocess"], "run") as run:
            with self.assertRaisesRegex(ValueError, "archive checksum"):
                RUNTIME["drive"](self.archive, "0" * 64, self.destination, RUNTIME["IMAGE"])
            self.destination.symlink_to(self.root / "absent")
            with self.assertRaisesRegex(ValueError, "already exists"):
                RUNTIME["drive"](self.archive, RUNTIME["digest"](self.archive), self.destination, RUNTIME["IMAGE"])
            run.assert_not_called()
        self.assertFalse((self.root / "absent").exists())


if __name__ == "__main__":
    unittest.main()

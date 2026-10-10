"""No-read boundaries for the versioned public source projection."""
import hashlib
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import manifest_builder


class SourceProjectionTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        subprocess.run(["git", "init", "--quiet"], cwd=self.root, check=True)

    def write(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic public source\n")
        return path

    def test_exact_archive_families_and_artifact_prefixes_have_no_content_coverage(self):
        names = ["fixtures/retained/archive" + suffix for suffix in (
            ".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tbz2", ".tar.xz",
            ".txz", ".tar.zst", ".tzst", ".zip", ".7z")]
        prefixes = ["docs/integrations/acceptance", *(
            f"docs/architecture/recoverable-agent-runtime/implementation/p{number}/evidence"
            for number in range(7)), "sdks/python/chio-hermes/evidence", "audits/evidence",
            "docs/integrations/session-credentials/evidence", "docs/evidence",
            "docs/research/openappa-2026-10-01/evidence", "labs/openappa-recovery/evidence",
            "formal/mutation/evidence"]
        names += [prefix + "/retained-source.rs" for prefix in prefixes]
        paths = [self.write(name) for name in names]
        original = os.open

        def reject_content(name, flags, *args, **kwargs):
            if not flags & os.O_DIRECTORY and os.fsdecode(name) in {path.name for path in paths}:
                raise AssertionError("excluded synthetic source body was opened")
            return original(name, flags, *args, **kwargs)

        with patch.object(os, "open", side_effect=reject_content):
            rows = manifest_builder.source_inventory(self.root)
        expected = [{"path": name, "state": "file", "mode": path.stat(follow_symlinks=False).st_mode & 0o7777,
                     "content_coverage": "metadata-only", "exclusion_reason":
                     "archive-file-policy" if index < 12 else "artifact-tree-policy"}
                    for index, (name, path) in enumerate(zip(names, paths))]
        self.assertEqual(rows, sorted(expected, key=lambda row: row["path"]))
        self.assertEqual(manifest_builder.SOURCE_INVENTORY_VERSION, "chio.source-inventory.v4")
        self.assertEqual(set(manifest_builder.ARTIFACT_PREFIXES), set(prefixes))

    def test_excluded_links_preserve_only_metadata(self):
        names = ["fixtures/retained.zip", "docs/integrations/acceptance/retained-source.rs"]
        for name in names:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.symlink_to("/never-read/synthetic-public-input")
        with patch.object(os, "readlink", side_effect=AssertionError("excluded link target was read")):
            rows = manifest_builder.source_inventory(self.root)
        self.assertEqual({row["path"] for row in rows}, set(names))
        self.assertTrue(all(row["state"] == "symlink" and row["content_coverage"] == "metadata-only"
                            and "target" not in row and "sha256" not in row for row in rows))

    def test_public_alias_cannot_follow_an_excluded_intermediate(self):
        self.write("fixtures/input.rs")
        excluded = self.root / "fixtures/retained.zip"
        excluded.symlink_to("input.rs")
        (self.root / "fixtures/input-alias.rs").symlink_to("retained.zip")
        original = os.readlink

        def reject_excluded(path, *args, **kwargs):
            if Path(path) == excluded:
                raise AssertionError("excluded intermediate link target was read")
            return original(path, *args, **kwargs)

        with patch.object(os, "readlink", side_effect=reject_excluded):
            with self.assertRaisesRegex(ValueError, "^campaign.symbolic_source$"):
                manifest_builder.source_inventory(self.root)

    def test_source_like_sibling_paths_remain_byte_bound(self):
        names = ["scripts/acceptance/source.py", "fixtures/qualification/source.py",
                 "crates/platform/chio-control-plane/src/recovery/tests/knowledge/qualification.rs",
                 "crates/platform/chio-control-plane/src/recovery/tests/knowledge/qualification/proof.rs",
                 "docs/integrations/acceptance-current/source.rs", "formal/mutation/source.rs",
                 "sdks/python/chio-hermes/src/example.py", "fixtures/archive.tar.rs", "fixtures/source.gz"]
        for name in names:
            self.write(name)
        self.assertEqual(manifest_builder.source_inventory(self.root), [
            {"path": name, "sha256": hashlib.sha256(b"synthetic public source\n").hexdigest()}
            for name in sorted(names)])

    def test_archive_suffix_on_an_ordinary_directory_does_not_hide_source(self):
        names = [f"crates/public{suffix}/src/lib.rs" for suffix in [".zip", ".TAR.GZ", ".7z"]]
        for name in names:
            self.write(name)
        self.assertEqual(manifest_builder.source_inventory(self.root), [
            {"path": name, "sha256": hashlib.sha256(b"synthetic public source\n").hexdigest()}
            for name in sorted(names)])

    def test_secret_precedence_remains_closed_and_content_free(self):
        names = ["fixtures/.env.retained.tar", "docs/integrations/acceptance/credentials.toml"]
        for name in names:
            self.write(name)
        rows = manifest_builder.source_inventory(self.root)
        self.assertEqual([row["exclusion_reason"] for row in rows], ["secret-path-policy"] * 2)
        self.assertTrue(all("sha256" not in row for row in rows))

    def test_archives_with_mixed_case_suffixes_remain_metadata_only(self):
        names = ["fixtures/retained.TAR.GZ", "fixtures/retained.ZIP"]
        for name in names:
            self.write(name)
        rows = manifest_builder.source_inventory(self.root)
        self.assertEqual([row["exclusion_reason"] for row in rows], ["archive-file-policy"] * 2)
        self.assertTrue(all("sha256" not in row for row in rows))

    def test_public_source_archive_omits_every_excluded_content_class(self):
        public = self.write("fixtures/input.rs")
        names = ["fixtures/retained.zip", "fixtures/credentials.toml",
                 "docs/integrations/acceptance/retained-source.rs"]
        for name in names:
            self.write(name)
        sources = manifest_builder.source_inventory(self.root)
        original = os.open

        def reject_excluded(name, flags, *args, **kwargs):
            if not flags & os.O_DIRECTORY and os.fsdecode(name) in {Path(name).name for name in names}:
                raise AssertionError("excluded synthetic content was opened while archiving")
            return original(name, flags, *args, **kwargs)

        with tempfile.TemporaryDirectory() as output_directory:
            archive_path = Path(output_directory) / "public-source.tar.gz"
            with patch.object(os, "open", side_effect=reject_excluded):
                manifest_builder.write_source_archive(self.root, sources, archive_path)
            with tarfile.open(archive_path, "r:gz") as archive:
                self.assertEqual(archive.getnames(), [str(public.relative_to(self.root))])
                stream = archive.extractfile(archive.getmembers()[0])
                self.assertIsNotNone(stream)
                self.assertEqual(stream.read(), b"synthetic public source\n")


if __name__ == "__main__":
    unittest.main()

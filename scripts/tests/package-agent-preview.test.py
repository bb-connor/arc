#!/usr/bin/env python3
"""Check archive integrity and exclusion of local credentials and runtime state."""

import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest


SCRIPT = Path(__file__).resolve().parents[1] / "package-agent-preview.py"
SPEC = importlib.util.spec_from_file_location("package_agent_preview", SCRIPT)
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class PreviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.installation = self.root / "installation"
        self.installation.mkdir()
        self.output = self.root / "preview.tar.gz"
        self.report = {
            "kind": "chio.local-installation-acceptance.v1",
            "source_revision": "a" * 40,
            "source_dirty": False,
            "release_qualified": False,
            "activation_restore_verified": True,
            "build_profile": "dev",
            "packages": {name: "0.2.0" for name in PACKAGE.PACKAGES},
            "sha256": {},
            "mcp_adoption": {"effects": 4, "verified_receipts": 6},
            "langchain": {"effects": 2, "verified_receipts": 3},
        }
        for name in PACKAGE.STATIC_FILES:
            self.add_artifact(name, b"source fixture\n")
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", header, 16, 3, 183)
        self.add_artifact("install/bin/chio", bytes(header))
        for name in PACKAGE.PACKAGES:
            self.add_artifact(f"wheels/{name.replace('-', '_')}-0.2.0-py3-none-any.whl", b"wheel fixture")
        self.save_report()

    def add_artifact(self, name, contents):
        path = self.installation / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(contents)
        self.report["sha256"][name] = hashlib.sha256(contents).hexdigest()

    def save_report(self):
        (self.installation / "acceptance.json").write_text(json.dumps(self.report))

    def enable_workbench(self):
        binary = (self.installation / "install/bin/chio").read_bytes()
        for name in PACKAGE.WORKBENCH_FILES:
            self.add_artifact(name, binary if name == "install/bin/chio-workbench" else b"workbench fixture\n")
        self.report["workbench"] = PACKAGE.WORKBENCH_ACCEPTANCE.copy()
        self.save_report()

    def assert_rejected(self):
        with self.assertRaises((ValueError, OSError)):
            PACKAGE.package(self.installation, self.output)
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".chio-preview-*.tmp")), [])

    def test_only_reviewed_artifacts_are_exported_and_all_hashes_match(self):
        for path in ("mcp-state/signing.seed", "langchain-state/receipts.sqlite", ".venv/pyvenv.cfg"):
            target = self.installation / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("do-not-export-this-private-material")
        self.report["operator_credentials"] = {"token": "do-not-export-this-private-material"}
        self.save_report()
        result = PACKAGE.package(self.installation, self.output)
        self.assertEqual(result["architecture"], "aarch64")
        self.assertFalse(result["release_qualified"])
        self.assertEqual(hashlib.sha256(self.output.read_bytes()).hexdigest(), result["sha256"])
        with tarfile.open(self.output) as archive:
            expected = set(PACKAGE.select_artifacts(self.report).values()) | {"README.md", "PREVIEW.json", "SHA256SUMS"}
            self.assertEqual(set(archive.getnames()), expected)
            for item in archive.getmembers():
                self.assertTrue(item.isfile())
                self.assertEqual(item.uid, 0)
                self.assertEqual(item.mtime, 0)
                self.assertEqual(item.mode, 0o755 if item.name == "bin/chio" else 0o644)
                self.assertNotIn(b"do-not-export-this-private-material", archive.extractfile(item).read())
            for line in archive.extractfile("SHA256SUMS").read().decode().splitlines():
                digest, path = line.split("  ", 1)
                self.assertEqual(hashlib.sha256(archive.extractfile(path).read()).hexdigest(), digest)
            metadata = json.load(archive.extractfile("PREVIEW.json"))
            self.assertFalse(metadata["publisher_authenticated"])
            self.assertFalse(metadata["release_qualified"])
            self.assertEqual(metadata["source_revision"], "a" * 40)

    def test_archive_bytes_are_reproducible(self):
        PACKAGE.package(self.installation, self.output)
        another = self.root / "another-name.tar.gz"
        PACKAGE.package(self.installation, another)
        self.assertEqual(self.output.read_bytes(), another.read_bytes())

    def test_workbench_binary_and_examples_require_recorded_acceptance(self):
        self.enable_workbench()
        PACKAGE.package(self.installation, self.output)
        with tarfile.open(self.output) as archive:
            self.assertEqual(archive.getmember("bin/chio-workbench").mode, 0o755)
            self.assertTrue(set(PACKAGE.WORKBENCH_FILES.values()) <= set(archive.getnames()))
            manifest = json.load(archive.extractfile("PREVIEW.json"))
            self.assertEqual(manifest["installation_acceptance"]["workbench"], PACKAGE.WORKBENCH_ACCEPTANCE)

    def test_changed_workbench_binary_and_examples_never_publish(self):
        self.enable_workbench()
        for name in PACKAGE.WORKBENCH_FILES:
            with self.subTest(name=name):
                path = self.installation / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed after acceptance")
                self.assert_rejected()
                path.write_bytes(original)

    def test_workbench_must_match_the_cli_architecture(self):
        self.enable_workbench()
        binary = bytearray((self.installation / "install/bin/chio-workbench").read_bytes())
        struct.pack_into("<H", binary, 18, 62)
        self.add_artifact("install/bin/chio-workbench", bytes(binary))
        self.save_report()
        self.assert_rejected()

    def test_workbench_requires_complete_files_and_successful_acceptance(self):
        self.report["workbench"] = PACKAGE.WORKBENCH_ACCEPTANCE.copy()
        self.save_report()
        self.assert_rejected()
        self.enable_workbench()
        for key, value in (("roles", 2), ("restart_verified", False), ("live_model_verified", True)):
            with self.subTest(key=key):
                self.report["workbench"] = {**PACKAGE.WORKBENCH_ACCEPTANCE, key: value}
                self.save_report()
                self.assert_rejected()
        del self.report["workbench"]
        self.save_report()
        self.assert_rejected()

    def test_changed_binary_wheel_example_or_requirements_never_publish_an_archive(self):
        for name in ("install/bin/chio", "wheels/chio_sdk-0.2.0-py3-none-any.whl", "examples/mcp-adoption/check.py", "requirements.txt"):
            with self.subTest(name=name):
                path = self.installation / name
                original = path.read_bytes()
                path.write_bytes(original + b"changed after acceptance")
                self.assert_rejected()
                path.write_bytes(original)

    def test_file_and_directory_symlinks_are_rejected(self):
        path = self.installation / "requirements.txt"
        saved = self.root / "requirements.txt"
        path.rename(saved)
        path.symlink_to(saved)
        self.assert_rejected()
        path.unlink()
        saved.rename(path)
        directory = self.installation / "examples"
        saved = self.root / "examples"
        directory.rename(saved)
        directory.symlink_to(saved, target_is_directory=True)
        self.assert_rejected()

    def test_failed_dirty_or_incomplete_acceptance_is_rejected(self):
        changes = (("source_dirty", True), ("release_qualified", True), ("activation_restore_verified", False),
                   ("source_revision", "unknown"), ("build_profile", "unknown"),
                   ("mcp_adoption", {"effects": 2, "verified_receipts": 6}))
        for key, value in changes:
            with self.subTest(key=key):
                original = self.report[key]
                self.report[key] = value
                self.save_report()
                self.assert_rejected()
                self.report[key] = original

    def test_unknown_artifacts_and_path_traversal_are_rejected(self):
        for name in ("mcp-state/signing.seed", "wheels/../secret.whl", "/tmp/secret",
                     "wheels//chio_sdk-0.2.0-py3-none-any.whl", "wheels/./chio_sdk-0.2.0-py3-none-any.whl"):
            self.report["sha256"][name] = "a" * 64
            self.save_report()
            self.assert_rejected()
            del self.report["sha256"][name]

    def test_missing_example_hash_or_wrong_wheel_version_is_rejected(self):
        digest = self.report["sha256"].pop("examples/mcp-adoption/check.py")
        self.save_report()
        self.assert_rejected()
        self.report["sha256"]["examples/mcp-adoption/check.py"] = digest
        self.report["packages"]["chio-sdk"] = "0.3.0"
        self.save_report()
        self.assert_rejected()

    def test_existing_output_and_symlinks_are_not_overwritten(self):
        self.output.write_bytes(b"operator file")
        with self.assertRaises(ValueError):
            PACKAGE.package(self.installation, self.output)
        self.assertEqual(self.output.read_bytes(), b"operator file")
        self.output.unlink()
        target = self.root / "other"
        target.write_bytes(b"operator file")
        self.output.symlink_to(target)
        with self.assertRaises(ValueError):
            PACKAGE.package(self.installation, self.output)
        self.assertEqual(target.read_bytes(), b"operator file")

    def test_output_inside_installation_is_rejected(self):
        with self.assertRaises(ValueError):
            PACKAGE.package(self.installation, self.installation / "bundle.tar.gz")

    def test_unsupported_executable_format_is_rejected(self):
        self.add_artifact("install/bin/chio", b"this is not an executable")
        self.save_report()
        self.assert_rejected()

    def test_oversized_sparse_artifacts_are_rejected_before_reading(self):
        with (self.installation / "install/bin/chio").open("r+b") as stream:
            stream.truncate(PACKAGE.MAX_BYTES + 1)
        self.assert_rejected()

    def test_duplicate_report_members_are_rejected(self):
        path = self.installation / "acceptance.json"
        path.write_text('{"source_dirty":false,"source_dirty":true}')
        self.assert_rejected()


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Exercise source and Cargo resolution substitution at the fork audit boundary."""

import hashlib
import importlib.util
import shutil
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "check-aws-lc-fork.py"
SPEC = importlib.util.spec_from_file_location("fork_check", SCRIPT)
CHECK = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECK)


class ForkBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.fork = self.root / "third_party/aws-lc-rs-chio"
        self.fork.mkdir(parents=True)
        (self.fork / "Cargo.toml").write_text('[package]\nname = "aws-lc-rs"\n')
        (self.fork / "build.rs").write_text("fn main() {}\n")
        self.files = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.fork.iterdir()
        }
        self.metadata = {
            "packages": [{
                "id": "fork", "name": "aws-lc-rs", "version": "1.18.1",
                "source": None, "manifest_path": str(self.fork / "Cargo.toml"),
            }],
            "resolve": {"nodes": [{"id": "fork", "features": ["alloc", "aws-lc-sys"]}]},
        }

    def test_reviewed_tree_and_path_resolution_are_accepted(self):
        CHECK.verify_source_tree(self.fork, self.files)
        CHECK.verify_resolution(self.metadata, self.fork)

    def test_modified_source_requires_another_audit(self):
        (self.fork / "build.rs").write_text('fn main() { panic!("changed"); }\n')
        with self.assertRaises(CHECK.AuditError):
            CHECK.verify_source_tree(self.fork, self.files)

    def test_unlisted_source_and_omitted_source_are_rejected(self):
        (self.fork / "injected.rs").write_text("fn injected() {}\n")
        with self.assertRaises(CHECK.AuditError):
            CHECK.verify_source_tree(self.fork, self.files)
        (self.fork / "injected.rs").unlink()
        del self.files["build.rs"]
        with self.assertRaises(CHECK.AuditError):
            CHECK.verify_source_tree(self.fork, self.files)

    def test_symlink_cannot_supply_reviewed_bytes(self):
        outside = self.root / "outside.rs"
        (self.fork / "build.rs").rename(outside)
        (self.fork / "build.rs").symlink_to(outside)
        with self.assertRaises(CHECK.AuditError):
            CHECK.verify_source_tree(self.fork, self.files)

    def test_registry_and_alternate_path_substitutions_are_rejected(self):
        package = self.metadata["packages"][0]
        package["source"] = "registry+https://github.com/rust-lang/crates.io-index"
        with self.assertRaises(CHECK.AuditError):
            CHECK.verify_resolution(self.metadata, self.fork)
        package["source"] = None
        package["manifest_path"] = str(self.root / "replacement/Cargo.toml")
        with self.assertRaises(CHECK.AuditError):
            CHECK.verify_resolution(self.metadata, self.fork)

    def test_additional_registry_copy_is_rejected(self):
        package = dict(self.metadata["packages"][0])
        package.update(id="registry", source="registry+https://github.com/rust-lang/crates.io-index")
        self.metadata["packages"].append(package)
        with self.assertRaises(CHECK.AuditError):
            CHECK.verify_resolution(self.metadata, self.fork)

    def test_unaudited_deployment_feature_is_rejected(self):
        self.metadata["resolve"]["nodes"][0]["features"].append("legacy-des")
        with self.assertRaises(CHECK.AuditError):
            CHECK.verify_resolution(self.metadata, self.fork)

    def test_registry_review_and_native_requirements_cannot_be_weakened(self):
        repository = SCRIPT.parent.parent
        chain = self.root / "supply-chain"
        chain.mkdir()
        for name in ("config.toml", "audits.toml"):
            shutil.copyfile(repository / "supply-chain" / name, chain / name)
        shutil.copyfile(repository / "third_party/aws-lc-rs-chio/Cargo.toml", self.fork / "Cargo.toml")
        CHECK.verify_policy(self.root)
        config = chain / "config.toml"
        original = config.read_text()
        changed = original.replace('aws-lc-sys = "safe-to-deploy"', 'aws-lc-sys = "safe-to-run"', 1)
        self.assertNotEqual(original, changed)
        config.write_text(changed)
        with self.assertRaises(CHECK.AuditError):
            CHECK.verify_policy(self.root)
        config.write_text(original)
        audits = chain / "audits.toml"
        audits.write_text(audits.read_text().replace(
            '[criteria.aws-lc-upstream-reviewed]',
            '[criteria.aws-lc-upstream-reviewed]\nimplies = "safe-to-deploy"',
        ))
        with self.assertRaises(CHECK.AuditError):
            CHECK.verify_policy(self.root)


if __name__ == "__main__":
    unittest.main()

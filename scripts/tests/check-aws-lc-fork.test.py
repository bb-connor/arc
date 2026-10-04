#!/usr/bin/env python3
"""Exercise source and Cargo resolution substitution at the fork audit boundary."""

import hashlib
import importlib.util
import os
import shutil
import subprocess
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

    def test_repeated_composite_builds_preserve_the_audited_tree(self):
        scripts = self.root / "scripts"
        scripts.mkdir()
        wrapper = scripts / "check-supply-chain.sh"
        shutil.copyfile(SCRIPT.parent / wrapper.name, wrapper)
        binaries = self.root / "bin"
        binaries.mkdir()
        # Model Cargo's documented target-directory selection. The real source
        # inventory checker must still accept the tree after repeated builds.
        cargo = binaries / "cargo"
        cargo.write_text(
            '#!/bin/sh\nset -eu\n'
            'if [ "$1" = test ]; then\n'
            '  build_dir="${CARGO_TARGET_DIR:-third_party/aws-lc-rs-chio/target}"\n'
            '  mkdir -p "$build_dir"\n'
            '  printf compiled > "$build_dir/regression-artifact"\n'
            'fi\n'
        )
        python = binaries / "python3"
        python.write_text('#!/bin/sh\nexit 0\n')
        cargo.chmod(0o755)
        python.chmod(0o755)
        env = dict(os.environ, PATH=f"{binaries}:{os.environ['PATH']}")
        env.pop("CARGO_TARGET_DIR", None)
        for _ in range(2):
            subprocess.run(["bash", str(wrapper)], env=env, check=True)
            CHECK.verify_source_tree(self.fork, self.files)
        self.assertTrue((self.root / "target/aws-lc-audit/regression-artifact").is_file())
        external = self.root / "external-target"
        env["CARGO_TARGET_DIR"] = str(external)
        subprocess.run(["bash", str(wrapper)], env=env, check=True)
        self.assertTrue((external / "regression-artifact").is_file())
        CHECK.verify_source_tree(self.fork, self.files)


if __name__ == "__main__":
    unittest.main()

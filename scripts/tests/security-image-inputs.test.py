#!/usr/bin/env python3
"""The trusted image must use the original bounded, read-only CA package."""

import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "check_security_ci_contract", ROOT / "scripts/check-security-ci-contract.py"
)
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)
PACKAGE = Path("deploy/docker/ca-certificates-20260611-r0.apk")
DOCKERFILE = ROOT / "deploy/docker/Dockerfile.security-evidence-runner"


class SecurityImageInputs(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        for relative in (
            PACKAGE, Path("deploy/docker/security-evidence-apk.lock"),
            Path("Cargo.lock"), Path("rust-toolchain.toml"),
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.document = DOCKERFILE.read_text()

    def validate(self, document=None):
        CHECKER.validate_security_dockerfile(self.root, document or self.document)

    def test_original_package_and_readonly_build_mount(self):
        self.validate()
        self.assertIn(
            f"--mount=type=bind,source={PACKAGE},"
            "target=/tmp/ca-certificates-20260611-r0.apk,readonly",
            self.document,
        )
        self.assertNotIn("wget ", self.document)

    def test_missing_input_is_refused(self):
        (self.root / PACKAGE).unlink()
        with self.assertRaises(CHECKER.ContractError):
            self.validate()

    def test_tampered_same_length_input_is_refused(self):
        target = self.root / PACKAGE
        original = target.read_bytes()
        target.write_bytes(bytes([original[0] ^ 1]) + original[1:])
        with self.assertRaises(CHECKER.ContractError):
            self.validate()

    def test_truncated_and_oversized_inputs_are_refused(self):
        target = self.root / PACKAGE
        original = target.read_bytes()
        for changed in (original[:-1], original + b"x"):
            with self.subTest(length=len(changed)):
                target.write_bytes(changed)
                with self.assertRaises(CHECKER.ContractError):
                    self.validate()

    def test_linked_and_nonregular_inputs_are_refused(self):
        target = self.root / PACKAGE
        target.unlink()
        target.symlink_to(ROOT / PACKAGE)
        with self.assertRaises(CHECKER.ContractError):
            self.validate()
        target.unlink()
        target.mkdir()
        with self.assertRaises(CHECKER.ContractError):
            self.validate()

    def test_writable_input_mount_is_refused(self):
        changed = self.document.replace(".apk,readonly", ".apk,rw")
        self.assertNotEqual(changed, self.document)
        with self.assertRaises(CHECKER.ContractError):
            self.validate(changed)


if __name__ == "__main__":
    unittest.main()

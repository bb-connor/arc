#!/usr/bin/env python3
"""The trusted image must install only the vendored, digest-bound, signed APK closure."""

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
ARCHIVES = Path("deploy/docker/security-evidence-apks")
PACKAGE = ARCHIVES / "ca-certificates-20260611-r0.apk"
OTHER_ARCHIVE = ARCHIVES / "zlib-1.3.2-r1.apk"
MANIFEST = ARCHIVES / "SHA256SUMS"
PROVENANCE = Path("deploy/docker/security-evidence-apk-archives.json")
DOCKERFILE = ROOT / "deploy/docker/Dockerfile.security-evidence-runner"
INSTALL = "apk add --no-network --no-cache --repositories-file /dev/null"


class SecurityImageInputs(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        shutil.copytree(ROOT / ARCHIVES, self.root / ARCHIVES)
        for relative in (
            PROVENANCE,
            Path("deploy/docker/security-evidence-apk.lock"),
            Path("Cargo.lock"),
            Path("rust-toolchain.toml"),
        ):
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        self.document = DOCKERFILE.read_text()

    def validate(self, document=None):
        CHECKER.validate_security_dockerfile(self.root, document or self.document)

    def assert_refused(self, document=None):
        with self.assertRaises(CHECKER.ContractError):
            self.validate(document)

    def test_vendored_closure_and_readonly_build_mount(self):
        self.validate()
        self.assertIn(
            f"--mount=type=bind,source={ARCHIVES},"
            "target=/tmp/security-evidence-apks,readonly",
            self.document,
        )
        self.assertIn(INSTALL, self.document)
        self.assertNotIn("--allow-untrusted", self.document)
        self.assertNotIn("wget ", self.document)

    def test_missing_input_is_refused(self):
        for relative in (PACKAGE, OTHER_ARCHIVE, MANIFEST, PROVENANCE):
            with self.subTest(relative=str(relative)):
                target = self.root / relative
                original = target.read_bytes()
                target.unlink()
                self.assert_refused()
                target.write_bytes(original)
                self.validate()

    def test_tampered_same_length_input_is_refused(self):
        for relative in (PACKAGE, OTHER_ARCHIVE, MANIFEST, PROVENANCE):
            with self.subTest(relative=str(relative)):
                target = self.root / relative
                original = target.read_bytes()
                target.write_bytes(bytes([original[0] ^ 1]) + original[1:])
                self.assert_refused()
                target.write_bytes(original)
                self.validate()

    def test_truncated_and_oversized_inputs_are_refused(self):
        for relative in (PACKAGE, OTHER_ARCHIVE):
            target = self.root / relative
            original = target.read_bytes()
            for changed in (original[:-1], original + b"x"):
                with self.subTest(relative=str(relative), length=len(changed)):
                    target.write_bytes(changed)
                    self.assert_refused()
            target.write_bytes(original)
            self.validate()

    def test_extra_archive_is_refused(self):
        shutil.copyfile(
            self.root / OTHER_ARCHIVE, self.root / ARCHIVES / "zlib-extra-1.3.2-r1.apk"
        )
        self.assert_refused()

    def test_linked_and_nonregular_inputs_are_refused(self):
        for relative in (PACKAGE, OTHER_ARCHIVE, MANIFEST):
            with self.subTest(relative=str(relative)):
                target = self.root / relative
                original = target.read_bytes()
                backing = self.root / "backing"
                backing.write_bytes(original)
                target.unlink()
                target.symlink_to(backing)
                self.assert_refused()
                target.unlink()
                target.mkdir()
                self.assert_refused()
                target.rmdir()
                backing.unlink()
                target.write_bytes(original)
                self.validate()

    def test_linked_archive_directory_is_refused(self):
        archives = self.root / ARCHIVES
        moved = self.root / "moved-archives"
        archives.rename(moved)
        archives.symlink_to(moved, target_is_directory=True)
        self.assert_refused()

    def test_writable_input_mount_is_refused(self):
        changed = self.document.replace(
            "target=/tmp/security-evidence-apks,readonly",
            "target=/tmp/security-evidence-apks,rw",
        )
        self.assertNotEqual(changed, self.document)
        self.assert_refused(changed)

    def test_untrusted_or_networked_install_is_refused(self):
        for old, new in (
            (INSTALL, INSTALL + " --allow-untrusted"),
            (INSTALL, "apk add --no-cache --repositories-file /dev/null"),
            (INSTALL, "apk add --no-network --no-cache"),
            (' && test "$(ls -A | wc -l)" = 204 \\\n', ""),
            (" && sha256sum -c SHA256SUMS \\\n", ""),
        ):
            with self.subTest(old=old, new=new):
                changed = self.document.replace(old, new, 1)
                self.assertNotEqual(changed, self.document)
                self.assert_refused(changed)


if __name__ == "__main__":
    unittest.main()

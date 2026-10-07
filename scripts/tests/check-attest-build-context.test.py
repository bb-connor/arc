#!/usr/bin/env python3
"""Execute the actual cached build script against independent crate directories."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
CRATE = REPO / "crates/trust/chio-attest-verify"
FILES = ("trusted_root.json", "root.json")


class AttestationBuildContext(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="chio-attest-build-context-")
        cls.root = Path(cls.temporary.name)
        cls.original = cls.root / "original"
        cls.populate(cls.original)
        cls.binary = cls.root / "build-script"
        environment = os.environ.copy()
        environment["CARGO_MANIFEST_DIR"] = str(cls.original)
        result = subprocess.run(
            ["rustc", "--edition=2024", str(CRATE / "build.rs"), "-o", str(cls.binary)],
            cwd=REPO, env=environment, text=True, capture_output=True, check=False,
        )
        if result.returncode != 0:
            cls.temporary.cleanup()
            raise AssertionError("actual build script did not compile: " + result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    @classmethod
    def populate(cls, directory):
        trust = directory / "sigstore-root"
        trust.mkdir(parents=True)
        for filename in FILES:
            shutil.copyfile(CRATE / "sigstore-root" / filename, trust / filename)

    def setUp(self):
        self.current = self.root / self._testMethodName
        self.populate(self.current)

    def execute(self, manifest):
        environment = os.environ.copy()
        environment.pop("CARGO_MANIFEST_DIR", None)
        if manifest is not None:
            environment["CARGO_MANIFEST_DIR"] = str(manifest)
        return subprocess.run(
            [str(self.binary)], cwd=self.root, env=environment,
            text=True, capture_output=True, check=False,
        )

    def test_cached_script_watches_current_crate_materials(self):
        result = self.execute(self.current)
        self.assertEqual(result.returncode, 0, result.stderr)
        lines = result.stdout.splitlines()
        for filename in FILES:
            self.assertIn(
                "cargo:rerun-if-changed=" + str(self.current / "sigstore-root" / filename),
                lines,
            )
        self.assertNotIn(str(self.original), result.stdout)

    def test_current_missing_trusted_root_is_refused(self):
        missing = self.current / "sigstore-root/trusted_root.json"
        missing.unlink()
        result = self.execute(self.current)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(missing), result.stderr)

    def test_current_missing_tuf_root_is_refused(self):
        missing = self.current / "sigstore-root/root.json"
        missing.unlink()
        result = self.execute(self.current)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(str(missing), result.stderr)

    def test_missing_cargo_manifest_directory_is_refused(self):
        result = self.execute(None)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("CARGO_MANIFEST_DIR", result.stderr)


if __name__ == "__main__":
    unittest.main()

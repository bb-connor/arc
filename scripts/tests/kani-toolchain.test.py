#!/usr/bin/env python3
"""Regression controls for the pinned Kani compiler repair and cache identity."""

import importlib.util
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "kani_toolchain", ROOT / "scripts/kani-toolchain.py"
)
KANI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KANI)


class CompilerRepairTests(unittest.TestCase):
    def test_failed_prerequisite_install_cannot_replace_or_accept_compiler(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary) / "bundle"
            compiler = bundle / "bin/kani-compiler"
            compiler.parent.mkdir(parents=True)
            compiler.write_bytes(b"original release compiler")

            def fail_provisioning(arguments, **kwargs):
                # No source reconstruction or compiler build may precede the
                # cold toolchain's prerequisites. Fail at the external boundary.
                self.assertEqual(arguments[:3], ["rustup", "toolchain", "install"])
                self.assertIn("nightly-2026-08-21", arguments)
                self.assertEqual(
                    set(arguments[arguments.index("--component") + 1].split(",")),
                    {"llvm-tools", "rustc-dev", "rust-src", "rustfmt"},
                )
                raise subprocess.CalledProcessError(1, arguments)

            with patch.object(KANI, "run", side_effect=fail_provisioning):
                with self.assertRaises(subprocess.CalledProcessError):
                    KANI.install(bundle, Path(temporary))
            self.assertEqual(compiler.read_bytes(), b"original release compiler")
            self.assertFalse((bundle / KANI.MARKER).exists())
            self.assertFalse((bundle / "bin/kani-compiler.chio-new").exists())

    def test_exact_upstream_signature_repair(self):
        repaired = KANI.repair_intrinsics(KANI.ORIGINAL_SIGNATURE)
        self.assertEqual(repaired, KANI.REPAIRED_SIGNATURE)
        for changed in ("", KANI.REPAIRED_SIGNATURE, KANI.ORIGINAL_SIGNATURE * 2):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                KANI.repair_intrinsics(changed)

    def test_cache_is_bound_to_compiler_bytes_and_reviewed_revision(self):
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            compiler = bundle / "bin/kani-compiler"
            compiler.parent.mkdir()
            compiler.write_bytes(b"compiler fixture")
            with self.assertRaises(ValueError):
                KANI.check_bundle(bundle)
            KANI.record_bundle(bundle)
            KANI.check_bundle(bundle)
            compiler.write_bytes(b"different compiler")
            with self.assertRaises(ValueError):
                KANI.check_bundle(bundle)
            KANI.record_bundle(bundle)
            marker = bundle / KANI.MARKER
            marker.write_text(marker.read_text().replace(KANI.REVISION, "0" * 40))
            with self.assertRaises(ValueError):
                KANI.check_bundle(bundle)


if __name__ == "__main__":
    unittest.main()

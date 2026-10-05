#!/usr/bin/env python3
"""Regression controls for the pinned Kani compiler repair and cache identity."""

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "kani_toolchain", ROOT / "scripts/kani-toolchain.py"
)
KANI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(KANI)


class CompilerRepairTests(unittest.TestCase):
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

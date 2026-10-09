#!/usr/bin/env python3
"""Keep the single owner-approved open proof residual explicit and bounded."""

from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
TARGET = "public_expect_report_data_determinism_and_binding"
PAIR = f"chio-attest-verify::{TARGET}"
MARKER = 'open_residual = "KANI-ATTEST-DECOMP"'


class OpenResidualTests(unittest.TestCase):
    def run_manifest(self, body=None, *args):
        with tempfile.TemporaryDirectory() as raw:
            env = os.environ.copy()
            if body is not None:
                manifest = Path(raw) / "manifest.toml"
                manifest.write_text(body)
                env["KANI_MANIFEST"] = str(manifest)
            else:
                env.pop("KANI_MANIFEST", None)
            return subprocess.run(
                ["bash", str(ROOT / "scripts/run-kani-manifest.sh"), *args],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )

    def fixture(self, marker=MARKER, harness=TARGET, crate="chio-attest-verify"):
        return f'''schema = "chio.kani.multi-crate.v1"
[[harness]]
crate = "{crate}"
harness = "{harness}"
lane = "pr"
default_unwind = 136
timeout_secs = 1800
features = ["kani"]
unwinding_checks = true
require_cover = true
p256_encoder_bounds = true
{marker}
'''

    def test_actual_pr_list_reports_open_and_never_schedules_residual(self):
        result = self.run_manifest(None, "--list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(PAIR, result.stdout)
        self.assertIn("OPEN/UNPROVED", result.stderr)
        self.assertIn("KANI-ATTEST-DECOMP", result.stderr)
        self.assertIn("chio-weights::public_weights_hash_of_determinism_and_shape", result.stdout)

    def test_residual_only_list_is_empty_not_a_proof_pass(self):
        result = self.run_manifest(self.fixture(), "--list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertIn("OPEN/UNPROVED", result.stderr)

    def test_residual_only_execution_refuses_empty_match(self):
        result = self.run_manifest(self.fixture())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no harnesses matched", result.stderr)
        self.assertNotIn("harnesses passed", result.stdout)

    def test_dry_run_counts_only_the_other_harness(self):
        body = self.fixture() + """[[harness]]
crate = "fake-crate"
harness = "ordinary_proof"
lane = "pr"
default_unwind = 8
timeout_secs = 10
"""
        result = self.run_manifest(body, "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("1 harnesses matched (dry-run)", result.stdout)
        self.assertIn("ordinary_proof", result.stdout)
        self.assertNotIn(TARGET, result.stdout)
        self.assertIn("OPEN/UNPROVED", result.stderr)

    def test_wrong_id_or_value_type_refused(self):
        for marker in ('open_residual = "different"', 'open_residual = true', 'open_residual = ""'):
            with self.subTest(marker=marker):
                result = self.run_manifest(self.fixture(marker), "--list")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("residual", result.stderr)

    def test_residual_cannot_move_to_another_harness(self):
        for crate, harness in (("chio-attest-verify", "another_harness"), ("chio-weights", TARGET)):
            with self.subTest(crate=crate, harness=harness):
                result = self.run_manifest(self.fixture(crate=crate, harness=harness), "--list")
                self.assertNotEqual(result.returncode, 0)

    def test_duplicate_residual_refused(self):
        body = self.fixture()
        result = self.run_manifest(body + body[body.index("[[harness]]"):], "--list")
        self.assertNotEqual(result.returncode, 0)

    def test_public_gate_refuses_missing_or_extra_marker(self):
        source = (ROOT / ".kani/harnesses.toml").read_text()
        self.assertIn(MARKER, source)
        variants = (
            source.replace(MARKER, ""),
            source.replace('harness = "public_weights_hash_of_determinism_and_shape"',
                           'harness = "public_weights_hash_of_determinism_and_shape"\n' + MARKER),
        )
        for body in variants:
            with tempfile.TemporaryDirectory() as raw:
                manifest = Path(raw) / "manifest.toml"
                manifest.write_text(body)
                result = subprocess.run(
                    ["python3", str(ROOT / "scripts/check-kani-public-harnesses.py"),
                     "--multi-manifest", str(manifest)],
                    capture_output=True, text=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("residual", result.stderr)


if __name__ == "__main__":
    unittest.main()

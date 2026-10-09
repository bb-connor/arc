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
NOTICE = f"OPEN/UNPROVED: {PAIR} (KANI-ATTEST-DECOMP); not executed or counted as passed"
ORDINARY = """[[harness]]
crate = "fake-crate"
harness = "ordinary_proof"
lane = "pr"
default_unwind = 8
timeout_secs = 10
"""


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

    def execute_manifest(self, body, *args):
        """Run the manifest for real with an inert cargo that records each call."""
        with tempfile.TemporaryDirectory() as raw:
            manifest = Path(raw) / "manifest.toml"
            manifest.write_text(body)
            log = Path(raw) / "cargo.log"
            bin_dir = Path(raw) / "bin"
            bin_dir.mkdir()
            cargo = bin_dir / "cargo"
            cargo.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >>"$FAKE_CARGO_LOG"\n')
            cargo.chmod(0o755)
            env = os.environ.copy()
            env.update(
                KANI_MANIFEST=str(manifest),
                FAKE_CARGO_LOG=str(log),
                PATH=f"{bin_dir}{os.pathsep}{env['PATH']}",
            )
            result = subprocess.run(
                ["bash", str(ROOT / "scripts/run-kani-manifest.sh"), *args],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            return result, log.read_text() if log.exists() else ""

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

    def test_execution_summary_ends_by_naming_the_unexecuted_residual(self):
        result, calls = self.execute_manifest(self.fixture() + ORDINARY)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(TARGET, calls)
        self.assertIn("ordinary_proof", calls)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(
            lines[-2:],
            ["run-kani-manifest.sh: 1 harnesses passed (lane=pr)", NOTICE],
        )

    def test_execution_summary_omits_a_residual_outside_the_selection(self):
        result, calls = self.execute_manifest(self.fixture() + ORDINARY, "--crate", "fake-crate")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(TARGET, calls)
        self.assertNotIn(NOTICE, result.stdout)
        lines = [line for line in result.stdout.splitlines() if line.strip()]
        self.assertEqual(lines[-1], "run-kani-manifest.sh: 1 harnesses passed (lane=pr crate=fake-crate)")

    def test_ordinary_crates_named_like_record_tags_stay_enrolled(self):
        body = 'schema = "chio.kani.multi-crate.v1"\n'
        for crate in ("OPEN_RESIDUAL", "HARNESS", "ordinary-crate"):
            body += f"""[[harness]]
crate = "{crate}"
harness = "ordinary_proof"
lane = "pr"
default_unwind = 8
timeout_secs = 10
"""
        result = self.run_manifest(body, "--list")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "OPEN_RESIDUAL::ordinary_proof",
                "HARNESS::ordinary_proof",
                "ordinary-crate::ordinary_proof",
            ],
        )

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

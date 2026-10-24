#!/usr/bin/env python3
"""Self-test for scripts/check-apalache-formal-slice.py.

The gate reads the committed formal models, workflows and gate scripts. Each
test copies the files it reads into a temp tree, optionally breaks one marker,
and runs the copied script with `python3 -I`.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COPIED = (
    "formal/apalache",
    "formal/tla",
    "formal/MAPPING.md",
    "formal/proof-manifest.toml",
    ".github/workflows/apalache-safety.yml",
    ".github/workflows/apalache-temporal.yml",
    ".github/workflows/ci.yml",
    "scripts/check-apalache-formal-slice.py",
    "scripts/check-apalache-positive.sh",
    "scripts/check-distributed-revocation-temporal.sh",
    "scripts/check-distributed-revocation-refinement.sh",
    "scripts/check-revocation-propagation.py",
    "scripts/validate-distributed-revocation-trace.py",
    "crates/trust/chio-federation/tests/distributed_revocation_refinement.rs",
)
RECEIPT = "formal/apalache/ReceiptBeforeAllow.tla"
CUT = "formal/apalache/RevocationCutCompleteness.tla"
DROP = "formal/apalache/PostAdmissionDropGuard.tla"
DROP_CFG = "formal/apalache/MCPostAdmissionDropGuard.cfg"
REGISTRY = "formal/apalache/_negative_tests/REGISTRY.toml"
TEMPORAL = ".github/workflows/apalache-temporal.yml"
SAFETY = ".github/workflows/apalache-safety.yml"
MANIFEST = "formal/proof-manifest.toml"
TRACE_GATE = "scripts/check-distributed-revocation-refinement.sh"


class ApalacheFormalSliceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="chio-apalache-slice-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for rel in COPIED:
            source = ROOT / rel
            target = self.root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if source.is_dir():
                shutil.copytree(source, target)
            else:
                shutil.copyfile(source, target)

    def mutate(self, rel: str, old: str, new: str) -> None:
        path = self.root / rel
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text, f"{rel} no longer contains the marker {old!r}")
        path.write_text(text.replace(old, new), encoding="utf-8")

    def mutate_occurrence(self, rel: str, old: str, new: str, occurrence: int) -> None:
        path = self.root / rel
        text = path.read_text(encoding="utf-8")
        start = -len(old)
        for _ in range(occurrence + 1):
            start = text.find(old, start + len(old))
            self.assertGreaterEqual(start, 0)
        path.write_text(text[:start] + new + text[start + len(old):], encoding="utf-8")

    def run_check(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", "scripts/check-apalache-formal-slice.py"],
            cwd=self.root,
            capture_output=True,
            text=True,
            check=False,
        )

    def assert_red(self, check: str, message: str) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"FAIL: {check}: {message}", result.stderr)
        failing = [line for line in result.stderr.splitlines() if line.startswith("FAIL: ")]
        self.assertTrue(
            all(line.startswith(f"FAIL: {check}:") for line in failing),
            result.stderr,
        )

    def test_green(self) -> None:
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "check-apalache-formal-slice: OK")

    def test_red_receipt_before_allow_loses_call_binding(self) -> None:
        self.mutate(RECEIPT, "decision.cap", "decision.kap")
        self.assert_red(
            "check_receipt_before_allow",
            "ReceiptBeforeAllow must bind receipt evidence to the published call",
        )

    def test_red_missing_definition(self) -> None:
        self.mutate(RECEIPT, "PersistAllowReceipt", "PersistAllowEvidence")
        self.assert_red("check_receipt_before_allow", "missing definition: PersistAllowReceipt")

    def test_red_revocation_cut_loses_ancestor_check(self) -> None:
        self.mutate(CUT, "NoRevokedAncestor(root)", "TRUE")
        self.assert_red(
            "check_revocation_cut",
            "Delegate must reject delegation below any revoked ancestor",
        )

    def test_red_drop_guard_config_enables_a_mutation(self) -> None:
        self.mutate(DROP_CFG, 'Mutation = "none"', 'Mutation = "skip-child-release"')
        self.assert_red(
            "check_post_admission_drop_guard",
            "positive drop-guard config must keep the documented bounds and disable mutations",
        )

    def test_red_drop_guard_loses_ground_truth_anchor(self) -> None:
        self.mutate(DROP, "PostEffectObligation::enter", "PostEffectObligation::begin")
        self.assert_red(
            "check_post_admission_drop_guard",
            "drop-guard ground-truth header is missing PostEffectObligation::enter",
        )

    def test_red_negative_registry_schema_changes(self) -> None:
        self.mutate(REGISTRY, "chio.apalache-negative.v1", "chio.apalache-negative.v2")
        self.assert_red(
            "check_negative_registry", "negative registry schema must remain versioned"
        )

    def test_red_negative_registry_property_unmapped(self) -> None:
        self.mutate("formal/MAPPING.md", "`ReceiptBeforeAllow`", "`ReceiptBeforeAllowRenamed`")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn(
            "FAIL: check_negative_registry: negative registry property is not mapped:",
            result.stderr,
        )

    def test_red_temporal_workflow_becomes_advisory(self) -> None:
        self.mutate(TEMPORAL, "  temporal_verdict:\n", "  temporal_verdict:\n    continue-on-error: true\n")
        self.assert_red(
            "check_temporal_workflow",
            "apalache-temporal must be fail-closed, not continue-on-error advisory",
        )

    def test_red_temporal_gate_loses_strict_marker(self) -> None:
        rel = "scripts/check-distributed-revocation-temporal.sh"
        original = (self.root / rel).read_text(encoding="utf-8")
        for occurrence, config in enumerate((
            "formal/tla/MCDistributedRevocationTemporalRefinement.cfg",
            "formal/tla/MCDistributedRevocationTemporalWitness.cfg",
            "formal/tla/MCDistributedRevocationTemporal.cfg",
        )):
            with self.subTest(config=config):
                (self.root / rel).write_text(original, encoding="utf-8")
                self.mutate_occurrence(rel, "--no-deadlock", "", occurrence)
                self.assert_red(
                    "check_temporal_workflow",
                    f"distributed temporal command for {config} must set --no-deadlock",
                )

    def test_red_safety_workflow_loses_fetch_depth(self) -> None:
        self.mutate_occurrence(SAFETY, "fetch-depth: 0", "fetch-depth: 1", 0)
        self.assert_red(
            "check_safety_workflow_wiring",
            "apalache-negative must fetch commit objects named by its registry",
        )

    def test_green_spec_mutants_fetch_depth_is_not_governed(self) -> None:
        self.mutate_occurrence(SAFETY, "fetch-depth: 0", "fetch-depth: 1", 1)
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "check-apalache-formal-slice: OK")

    def test_red_inserted_job_cannot_supply_negative_job_history(self) -> None:
        self.mutate_occurrence(SAFETY, "fetch-depth: 0", "fetch-depth: 1", 0)
        original = (self.root / SAFETY).read_text(encoding="utf-8")
        for key in ("history-helper", '\"history-helper\"', "'history-helper'"):
            with self.subTest(key=key):
                (self.root / SAFETY).write_text(original, encoding="utf-8")
                self.mutate(
                    SAFETY,
                    "  spec-mutants:\n",
                    f"  {key}:\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          fetch-depth: 0\n\n  spec-mutants:\n",
                )
                self.assert_red(
                    "check_safety_workflow_wiring",
                    "apalache-negative must fetch commit objects named by its registry",
                )

    def test_red_safety_matrix_row_changes_timeout(self) -> None:
        self.mutate(SAFETY, "timeout_seconds: 1800", "timeout_seconds: 60")
        result = self.run_check()
        self.assertEqual(result.returncode, 1)
        self.assertIn("FAIL: check_safety_workflow_wiring: apalache-safety must", result.stderr)

    def test_red_negative_lane_enters_aggregate_gates(self) -> None:
        self.mutate(
            MANIFEST,
            "gate_commands = [\n",
            'gate_commands = [\n  "./scripts/check-apalache-negative.sh",\n',
        )
        self.assert_red(
            "check_negative_gate_boundary",
            "the pinned Apalache negative lane must not enter unprovisioned aggregate gates",
        )

    def test_red_trace_gate_loses_invariant(self) -> None:
        self.mutate(TRACE_GATE, "--inv=TraceSafety", "--inv=TraceTrue")
        self.assert_red(
            "check_distributed_trace_gate",
            "distributed trace gate is missing --inv=TraceSafety",
        )


if __name__ == "__main__":
    unittest.main()

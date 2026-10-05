#!/usr/bin/env python3
"""Bind source inputs without a cycle through the final signed evidence commit."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "derived_inputs_checker", ROOT / "scripts/check-security-adversarial-evidence.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load adversarial evidence checker")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class DerivedEvidenceInputs(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="chio-derived-evidence-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.package = self.root / "crates/fixture"
        (self.package / "src").mkdir(parents=True)
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/fixture"]\nresolver = "2"\n'
        )
        (self.root / "Cargo.lock").write_text("version = 3\n")
        (self.package / "Cargo.toml").write_text(
            '[package]\nname = "fixture"\nversion = "0.1.0"\nedition = "2021"\n'
        )
        self.source = self.package / "src/lib.rs"
        self.source.write_text("pub fn permits() -> bool { true }\n#[test]\nfn control() {}\n")
        self.evidence = self.root / "audits/evidence/enterprise-linux"
        self.evidence.parent.mkdir(parents=True)
        self.campaign = {
            "id": "fixture_campaign", "control_id": "control", "package": "fixture",
            "source": "crates/fixture/src/lib.rs", "function": "permits", "minimum_caught": 1,
            "outcomes": {"path": "audits/evidence/mutants/security/fixture_campaign/mutants.out/outcomes.json"},
        }
        self.control = {
            "id": "control", "package": "fixture", "test_source": "crates/fixture/src/lib.rs",
            "target_kind": "lib", "test_name": "control", "features": [], "required_target_os": [],
        }

    def digest(self) -> str:
        return CHECKER.campaign_input_digest(
            self.root, {"fixture": self.package}, self.campaign, self.control,
            self.root / "crates/core/chio-adversarial-suite/cases/fixture/fixture.json",
        )

    def test_evidence_commit_preserves_the_source_input_binding(self) -> None:
        before = self.digest()
        self.evidence.mkdir()
        # These are hashing fixtures, not accepted signed evidence. The separate
        # committed-evidence verifier authenticates the real document and policy.
        for name in (
            "enterprise-migration-canary.json",
            "enterprise-migration-canary.json.sha256",
            "enterprise-migration-binding-digest.txt",
        ):
            (self.evidence / name).write_text("first output\n")
            self.assertEqual(self.digest(), before, name)
            (self.evidence / name).write_text("refreshed output\n")
            self.assertEqual(self.digest(), before, name)

    def test_unknown_output_is_rejected(self) -> None:
        self.evidence.mkdir()
        (self.evidence / "extra.rs").write_text("pub fn extra() {}\n")
        with self.assertRaisesRegex(CHECKER.EvidenceError, "unexpected derived evidence entry"):
            self.digest()

    def test_nested_output_is_rejected(self) -> None:
        self.evidence.mkdir()
        (self.evidence / "enterprise-migration-canary.json").mkdir()
        with self.assertRaisesRegex(CHECKER.EvidenceError, "derived evidence entry is not a regular file"):
            self.digest()

    def test_linked_output_is_rejected(self) -> None:
        self.evidence.mkdir()
        (self.evidence / "enterprise-migration-canary.json").symlink_to(self.source)
        with self.assertRaisesRegex(CHECKER.EvidenceError, "derived evidence entry is not a regular file"):
            self.digest()

    def test_linked_output_directory_is_rejected(self) -> None:
        self.evidence.symlink_to(self.package, target_is_directory=True)
        with self.assertRaises(CHECKER.EvidenceError):
            self.digest()

    def test_linked_output_ancestor_is_rejected(self) -> None:
        self.evidence.parent.rmdir()
        self.evidence.parent.symlink_to(self.package, target_is_directory=True)
        with self.assertRaises(CHECKER.EvidenceError):
            self.digest()

    def test_replaced_output_directory_is_rejected(self) -> None:
        self.evidence.mkdir()
        scan = CHECKER.os.scandir

        def replace_opened_directory(descriptor: int):
            entries = scan(descriptor)
            self.evidence.rename(self.evidence.with_name("retired-output"))
            self.evidence.mkdir()
            return entries

        with mock.patch.object(CHECKER.os, "scandir", side_effect=replace_opened_directory):
            with self.assertRaisesRegex(CHECKER.EvidenceError, "output directory identity changed"):
                self.digest()

    def test_similar_sibling_directory_remains_a_bound_input(self) -> None:
        before = self.digest()
        sibling = self.evidence.with_name("enterprise-linux-inputs")
        sibling.mkdir()
        (sibling / "input.json").write_text("source data\n")
        self.assertNotEqual(self.digest(), before)

    def test_compilation_cannot_consume_derived_evidence(self) -> None:
        self.evidence.mkdir()
        path = self.evidence / "enterprise-migration-canary.json"
        path.write_text("derived output\n")
        self.source.write_text(
            self.source.read_text()
            + 'const EVIDENCE: &str = include_str!("../../../audits/evidence/enterprise-linux/enterprise-migration-canary.json");\n'
        )
        with self.assertRaisesRegex(CHECKER.EvidenceError, "excluded generated or derived input"):
            self.digest()


if __name__ == "__main__":
    unittest.main(verbosity=2)

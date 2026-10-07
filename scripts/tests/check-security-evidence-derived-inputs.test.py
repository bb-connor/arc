#!/usr/bin/env python3
"""Bind source inputs without a cycle through the final signed evidence commit."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
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

BOUNDARY_SPEC = importlib.util.spec_from_file_location(
    "derived_inputs_boundary", ROOT / "scripts/run-security-execution-container.py"
)
if BOUNDARY_SPEC is None or BOUNDARY_SPEC.loader is None:
    raise RuntimeError("unable to load isolated execution boundary")
BOUNDARY = importlib.util.module_from_spec(BOUNDARY_SPEC)
sys.modules[BOUNDARY_SPEC.name] = BOUNDARY
BOUNDARY_SPEC.loader.exec_module(BOUNDARY)


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

    def commit(self) -> str:
        environment = os.environ.copy()
        for key in tuple(environment):
            if key.startswith("GIT_"):
                environment.pop(key)
        commands = [
            ["git", "init", "--quiet"],
            ["git", "-c", "core.hooksPath=/dev/null", "add", "--all"],
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Evidence fixture",
             "-c", "user.email=fixture@invalid", "commit", "--quiet", "--no-gpg-sign", "-m", "fixture"],
        ]
        for command in commands:
            subprocess.run(command, cwd=self.root, env=environment, check=True, capture_output=True)
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.root, env=environment, text=True
        ).strip()

    def projection(self) -> Path:
        head = self.commit()
        identity = BOUNDARY.repository_identity(self.root, head, None)
        temporary = tempfile.TemporaryDirectory(prefix="chio-derived-projection-")
        self.addCleanup(temporary.cleanup)
        destination = Path(temporary.name) / "source"
        BOUNDARY.materialize_private_copy(identity, destination)
        return destination

    def add_dynamic_build(self) -> None:
        (self.root / "Cargo.lock").write_text(
            'version = 4\n\n[[package]]\nname = "fixture"\nversion = "0.1.0"\n'
        )
        (self.package / "build.rs").write_text(r'''
use std::{env, fs, io, path::PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?).join("../..");
    let path = root.join("audits/evidence")
        .join(["enterprise", "linux"].join("-"))
        .join(concat!("enterprise-migration", "-canary.json"));
    let value = match fs::read_to_string(path) {
        Ok(value) => value,
        Err(error) if error.kind() == io::ErrorKind::NotFound => "absent".to_owned(),
        Err(error) => return Err(error.into()),
    };
    fs::write(root.join("build-executed.marker"), "executed")?;
    println!("cargo:rustc-env=DERIVED_INPUT_STATE={}", value.trim());
    Ok(())
}
''')
        self.source.write_text(
            'pub fn permits() -> bool { env!("DERIVED_INPUT_STATE") == "absent" }\n'
            '#[test]\nfn control() { assert!(permits()); }\n'
        )

    def cargo_environment(self) -> dict[str, str]:
        environment = os.environ.copy()
        for key in tuple(environment):
            if key.startswith(("GIT_", "RUSTFLAGS", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER")):
                environment.pop(key)
        target = tempfile.TemporaryDirectory(prefix="chio-derived-target-")
        self.addCleanup(target.cleanup)
        environment.update(CARGO_TARGET_DIR=target.name, CARGO_INCREMENTAL="0", CARGO_NET_OFFLINE="true")
        return environment

    def test_fragmented_build_input_is_unavailable_before_and_after_publication(self) -> None:
        self.add_dynamic_build()
        for published in (False, True):
            with self.subTest(published=published):
                if published:
                    self.evidence.mkdir()
                    (self.evidence / "enterprise-migration-canary.json").write_text("visible-after-publication\n")
                projected = self.projection()
                result = subprocess.run(
                    ["cargo", "test", "--offline", "--locked", "--package", "fixture", "--lib"],
                    cwd=projected, env=self.cargo_environment(), text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120,
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn("test result: ok. 1 passed;", result.stdout)

    def test_projection_omits_only_the_three_regular_publication_outputs(self) -> None:
        self.evidence.mkdir()
        names = (
            "enterprise-migration-canary.json",
            "enterprise-migration-canary.json.sha256",
            "enterprise-migration-binding-digest.txt",
        )
        for name in names:
            (self.evidence / name).write_text("derived output\n")
        sibling = self.evidence.with_name("source-input.json")
        sibling.write_text("bound input\n")
        projected = self.projection()
        self.assertFalse((projected / "audits/evidence/enterprise-linux").exists())
        self.assertEqual((projected / "audits/evidence/source-input.json").read_bytes(), sibling.read_bytes())
        self.assertEqual((projected / "crates/fixture/src/lib.rs").read_bytes(), self.source.read_bytes())
        for name in names:
            self.assertEqual((self.evidence / name).read_text(), "derived output\n")

    def test_projection_rejects_unexpected_outputs(self) -> None:
        self.evidence.mkdir()
        (self.evidence / "input.rs").write_text("pub fn input() {}\n")
        with self.assertRaisesRegex(BOUNDARY.BoundaryError, "derived Linux evidence"):
            self.projection()

    def test_projection_rejects_executable_outputs(self) -> None:
        self.evidence.mkdir()
        output = self.evidence / "enterprise-migration-canary.json"
        output.write_text("executable output\n")
        output.chmod(0o755)
        with self.assertRaisesRegex(BOUNDARY.BoundaryError, "derived Linux evidence"):
            self.projection()

    def test_projection_rejects_linked_outputs(self) -> None:
        self.evidence.mkdir()
        (self.evidence / "enterprise-migration-canary.json").symlink_to("../../../crates/fixture/src/lib.rs")
        with self.assertRaisesRegex(BOUNDARY.BoundaryError, "derived Linux evidence"):
            self.projection()

    def test_projection_rejects_linked_output_ancestors(self) -> None:
        self.evidence.parent.rmdir()
        self.evidence.parent.symlink_to("../crates/fixture", target_is_directory=True)
        with self.assertRaisesRegex(BOUNDARY.BoundaryError, "derived Linux evidence"):
            self.projection()

    def test_direct_control_refuses_outputs_before_build_execution(self) -> None:
        self.add_dynamic_build()
        self.evidence.mkdir()
        (self.evidence / "enterprise-migration-canary.json").write_text("absent\n")
        control = {key: value for key, value in self.control.items() if key != "required_target_os"}
        with self.assertRaisesRegex(CHECKER.EvidenceError, "derived Linux evidence.*execution"):
            CHECKER.run_control(self.root, control, self.cargo_environment())
        self.assertFalse((self.root / "build-executed.marker").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)

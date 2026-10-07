#!/usr/bin/env python3
"""Keep targeted refresh discovery bounded while preserving source validation."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "refresh_scope_checker", ROOT / "scripts/check-security-adversarial-evidence.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("unable to load adversarial evidence checker")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)


class RefreshScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="chio-mutants-refresh-scope-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.cases = self.root / "cases"
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/first", "crates/second"]\nresolver = "2"\n'
        )
        self.case_paths: dict[str, Path] = {}
        for package, campaign in (
            ("first", "broker_proof_replay"),
            ("second", "broker_revocation_race"),
        ):
            directory = self.root / "crates" / package
            (directory / "src").mkdir(parents=True)
            (directory / "Cargo.toml").write_text(
                f'[package]\nname = "{package}"\nversion = "0.1.0"\nedition = "2021"\n'
            )
            (directory / "src/lib.rs").write_text(
                "pub fn permits() -> bool { true }\n"
                "#[test]\nfn control() { assert!(permits()); }\n"
            )
            case = {
                "schema_version": 1,
                "id": campaign,
                "class": campaign,
                "expected_verdict": "DENY",
                "expected_reason": "fixture denial",
                "threat_id": "fixture-threat",
                "pending": True,
                "artifact": {
                    "schema": "chio.adversarial-mutation-evidence.v1",
                    "controls": [{
                        "id": "control", "package": package,
                        "test_source": f"crates/{package}/src/lib.rs",
                        "target_kind": "lib", "test_name": "control",
                    }],
                    "campaigns": [{
                        "id": campaign, "control_id": "control", "package": package,
                        "source": f"crates/{package}/src/lib.rs", "function": "permits",
                        "minimum_caught": 1,
                        "mutant": {"genre": "FnValue", "replacement": "false"},
                        "outcomes": {
                            "path": f"audits/evidence/mutants/security/{campaign}/mutants.out/outcomes.json",
                        },
                    }],
                },
            }
            path = self.cases / campaign / f"{campaign}.json"
            path.parent.mkdir(parents=True)
            path.write_text(json.dumps(case))
            self.case_paths[package] = path

    def load(self, refresh: str | None = None) -> list[str]:
        # Execute the real pinned engine. The spy measures costly process work;
        # source discovery, filesystem reads and all case validation stay real.
        with mock.patch.object(
            CHECKER, "cargo_mutants_output", wraps=CHECKER.cargo_mutants_output
        ) as executed:
            cases, _ = CHECKER.load_cases(
                self.root, self.cases, False, True, refresh_campaign=refresh
            )
        self.assertEqual(len(cases), 2)
        commands = [call.args[0] for call in executed.call_args_list]
        return [command[command.index("-p") + 1] for command in commands if "--list-files" in command]

    def change_source(self, package: str, name: str) -> None:
        path = self.case_paths[package]
        case = json.loads(path.read_text())
        case["artifact"]["campaigns"][0]["source"] = f"crates/{package}/src/{name}"
        path.write_text(json.dumps(case))

    def test_refresh_discovers_only_the_selected_package(self) -> None:
        self.assertEqual(self.load("broker_proof_replay"), ["first"])

    def test_pending_inventory_starts_no_candidate_cargo_commands(self) -> None:
        self.assertEqual(self.load(""), [])

    def test_ordinary_validation_discovers_every_package(self) -> None:
        self.assertEqual(self.load(), ["first", "second"])

    def test_ordinary_validation_rejects_an_undiscoverable_sibling(self) -> None:
        (self.root / "crates/second/src/orphan.rs").write_text("pub fn permits() {}\n")
        self.change_source("second", "orphan.rs")
        with self.assertRaisesRegex(CHECKER.EvidenceError, "not cargo-mutants-discoverable"):
            self.load()

    def test_refresh_rejects_an_undiscoverable_selected_source(self) -> None:
        (self.root / "crates/first/src/orphan.rs").write_text("pub fn permits() {}\n")
        self.change_source("first", "orphan.rs")
        with self.assertRaisesRegex(CHECKER.EvidenceError, "not cargo-mutants-discoverable"):
            self.load("broker_proof_replay")

    def test_refresh_still_rejects_a_linked_sibling_source(self) -> None:
        (self.root / "crates/second/src/alias.rs").symlink_to("lib.rs")
        self.change_source("second", "alias.rs")
        with self.assertRaises(CHECKER.EvidenceError):
            self.load("broker_proof_replay")

    def test_refresh_still_rejects_a_missing_sibling_function(self) -> None:
        path = self.case_paths["second"]
        case = json.loads(path.read_text())
        case["artifact"]["campaigns"][0]["function"] = "absent_function"
        path.write_text(json.dumps(case))
        with self.assertRaisesRegex(CHECKER.EvidenceError, "function absent_function is absent"):
            self.load("broker_proof_replay")


if __name__ == "__main__":
    unittest.main(verbosity=2)

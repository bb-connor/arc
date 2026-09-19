#!/usr/bin/env python3
"""FIPS/nonce CI contract fixtures, checked against the owning workflow."""

import copy
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
workflow = yaml.safe_load((ROOT / ".github/workflows/chio-tee-fips.yml").read_text())
events = workflow.get("on", workflow.get(True))
assert "workflow_call" in events, "FIPS/nonce coverage must be reusable by required CI"
ci = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
assert "nonce-fips-contract" in ci["jobs"]["security-contract-required"]["needs"], (
    "Security contract must join nonce/FIPS"
)
print("FIPS required source routing passed")

SPEC = importlib.util.spec_from_file_location(
    "security_ci", ROOT / "scripts/check-security-ci-contract.py"
)
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)
FIPS = CHECKER.load_workflow(ROOT / ".github/workflows/chio-tee-fips.yml")
CI = CHECKER.load_workflow(ROOT / ".github/workflows/ci.yml")


class FipsContractTests(unittest.TestCase):
    def validate(self, fips, ci):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            workflows = directory / ".github/workflows"
            workflows.mkdir(parents=True)
            (workflows / "chio-tee-fips.yml").write_text(yaml.dump(fips))
            (workflows / "ci.yml").write_text(yaml.dump(ci))
            CHECKER.validate_nonce_fips_contract(directory)

    def test_current_reviewed_inventory_passes(self):
        self.validate(FIPS, CI)

    def test_each_cargo_command_requires_locked_resolution(self):
        cases = 0
        for job_id, job in FIPS["jobs"].items():
            for index, step in enumerate(job["steps"]):
                if "cargo " in step.get("run", "") and "--locked" in step["run"]:
                    with self.subTest(job=job_id, step=step.get("name")):
                        changed = copy.deepcopy(FIPS)
                        changed["jobs"][job_id]["steps"][index]["run"] = step[
                            "run"
                        ].replace("--locked ", "", 1)
                        with self.assertRaises(CHECKER.ContractError):
                            self.validate(changed, CI)
                        cases += 1
        self.assertGreater(cases, 25)

    def test_pinned_toolchain_and_compiler_identity_cannot_be_dropped(self):
        for job_id, job in FIPS["jobs"].items():
            index = next(
                index
                for index, step in enumerate(job["steps"])
                if step.get("name") == "Install Rust toolchain"
            )
            for original, substitute in [
                ("1.94.1", "stable"),
                ("rustc --version --verbose", "true"),
                ("cargo --version", "true"),
            ]:
                with self.subTest(job=job_id, marker=original):
                    changed = copy.deepcopy(FIPS)
                    changed["jobs"][job_id]["steps"][index]["run"] = job["steps"][
                        index
                    ]["run"].replace(original, substitute)
                    with self.assertRaises(CHECKER.ContractError):
                        self.validate(changed, CI)

    def test_nonce_test_identity_cannot_be_removed(self):
        changed = copy.deepcopy(FIPS)
        step = next(
            step
            for step in changed["jobs"]["threshold-crypto-floor"]["steps"]
            if step.get("name") == "Exact nonce validation and consumption boundary"
        )
        step["run"] = step["run"].replace(
            "kernel::tests::nonce_admission::nonce_admission_strict_reservation_requires_a_presented_nonce",
            "kernel::tests::another_case",
        )
        with self.assertRaises(CHECKER.ContractError):
            self.validate(changed, CI)

    def test_job_privileges_and_bypass_flags_are_closed(self):
        for field, value in [
            ("permissions", {"contents": "write"}),
            ("secrets", "inherit"),
            ("if", "false"),
            ("continue-on-error", "true"),
            ("runs-on", "self-hosted"),
        ]:
            with self.subTest(field=field):
                changed = copy.deepcopy(FIPS)
                changed["jobs"]["fips-smoke"][field] = value
                with self.assertRaises(CHECKER.ContractError):
                    self.validate(changed, CI)

    def test_caller_cannot_skip_or_grant_privileges(self):
        for field, value in [
            ("if", "false"),
            ("secrets", "inherit"),
            ("permissions", {"contents": "write"}),
        ]:
            changed = copy.deepcopy(CI)
            changed["jobs"]["nonce-fips-contract"][field] = value
            with self.subTest(field=field), self.assertRaises(CHECKER.ContractError):
                self.validate(FIPS, changed)

    def test_aggregate_requires_success_and_dependency(self):
        changed = copy.deepcopy(CI)
        changed["jobs"]["security-contract-required"]["needs"].remove(
            "nonce-fips-contract"
        )
        with self.assertRaises(CHECKER.ContractError):
            self.validate(FIPS, changed)
        changed = copy.deepcopy(CI)
        step = changed["jobs"]["security-contract-required"]["steps"][0]
        step["run"] = step["run"].replace(
            "test '${{ needs.nonce-fips-contract.result }}' = success", "true"
        )
        with self.assertRaises(CHECKER.ContractError):
            self.validate(FIPS, changed)

    def test_direct_triggers_keep_non_main_and_manual_coverage_without_duplicate_main(
        self,
    ):
        for event, value in [
            ("workflow_dispatch", None),
            ("workflow_call", None),
            (
                "push",
                {
                    "branches": ["main", "project/**"],
                    "paths": FIPS["on"]["push"]["paths"],
                },
            ),
            ("pull_request", {"paths": FIPS["on"]["pull_request"]["paths"]}),
        ]:
            changed = copy.deepcopy(FIPS)
            if value is None:
                changed["on"].pop(event)
            else:
                changed["on"][event] = value
            with self.subTest(event=event), self.assertRaises(CHECKER.ContractError):
                self.validate(changed, CI)


if __name__ == "__main__":
    unittest.main()

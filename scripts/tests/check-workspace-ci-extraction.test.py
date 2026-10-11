#!/usr/bin/env python3
"""Exercise the required aggregate and the unchanged workspace test prerequisites."""

from __future__ import annotations

import copy
import importlib.util
import itertools
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "workspace_ci_contract", ROOT / "scripts/check-security-ci-contract.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load security CI contract")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)
LIVE = CHECKER.load_workflow(ROOT / ".github/workflows/ci.yml")


class WorkspaceCiExtractionTests(unittest.TestCase):
    def rejected(self, changed: dict, message: str) -> None:
        with self.assertRaisesRegex(CHECKER.ContractError, message):
            CHECKER.validate_build_lint_test(changed)

    def test_live_workflow_preserves_required_aggregate(self) -> None:
        CHECKER.validate_build_lint_test(LIVE)

    def test_aggregate_requires_both_successful_results(self) -> None:
        body = LIVE["jobs"]["check"]["steps"][0]["run"]
        states = ("success", "failure", "cancelled", "skipped", "", "timed_out")
        for build, tests in itertools.product(states, repeat=2):
            with self.subTest(build=build, tests=tests):
                command = body.replace("${{ needs.build-lint.result }}", build).replace(
                    "${{ needs.workspace-tests.result }}", tests
                )
                self.assertNotIn("${{", command)
                result = subprocess.run(
                    ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", command],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(result.returncode == 0, build == tests == "success")

    def test_aggregate_refuses_missing_dependencies_or_final_evaluation(self) -> None:
        for key in ("needs", "if", "steps"):
            changed = copy.deepcopy(LIVE)
            del changed["jobs"]["check"][key]
            with self.subTest(key=key):
                self.rejected(changed, "exact fail-closed body")
        for child in ("build-lint", "workspace-tests"):
            changed = copy.deepcopy(LIVE)
            changed["jobs"]["check"]["needs"].remove(child)
            with self.subTest(child=child):
                self.rejected(changed, "exact fail-closed body")

    def test_aggregate_refuses_tolerated_failure_and_early_exit(self) -> None:
        for key, value in (("continue-on-error", "true"), ("if", "${{ success() }}")):
            changed = copy.deepcopy(LIVE)
            changed["jobs"]["check"][key] = value
            with self.subTest(key=key):
                self.rejected(changed, "exact fail-closed body")
        for old, new in ((" = success", " != failure"), ("set -euo pipefail", "exit 0")):
            changed = copy.deepcopy(LIVE)
            step = changed["jobs"]["check"]["steps"][0]
            step["run"] = step["run"].replace(old, new)
            with self.subTest(replacement=new):
                self.rejected(changed, "exact fail-closed body")

    def test_required_context_cannot_move_or_be_duplicated(self) -> None:
        for child in ("build-lint", "workspace-tests"):
            changed = copy.deepcopy(LIVE)
            changed["jobs"][child]["name"] = "Build, lint, test"
            with self.subTest(child=child):
                self.rejected(changed, "exact unique aggregate")

    def test_children_cannot_be_conditional_or_tolerate_failure(self) -> None:
        for child, field in itertools.product(
            ("build-lint", "workspace-tests"),
            ("if", "continue-on-error", "strategy", "needs", "env", "container"),
        ):
            changed = copy.deepcopy(LIVE)
            changed["jobs"][child][field] = "false"
            with self.subTest(child=child, field=field):
                self.rejected(changed, "unconditional execution contract")

    def test_children_keep_host_and_original_budget(self) -> None:
        for child, (field, value) in itertools.product(
            ("build-lint", "workspace-tests"),
            (("runs-on", "windows-latest"), ("timeout-minutes", "361")),
        ):
            changed = copy.deepcopy(LIVE)
            changed["jobs"][child][field] = value
            with self.subTest(child=child, field=field):
                self.rejected(changed, "unconditional execution contract")

    def test_workspace_command_cannot_filter_targets_tests_or_features(self) -> None:
        for suffix in (" --lib", " --tests", " --features iroh", " -- --skip security", " -- --ignored"):
            changed = copy.deepcopy(LIVE)
            changed["jobs"]["workspace-tests"]["steps"][-1]["run"] += suffix
            with self.subTest(suffix=suffix):
                self.rejected(changed, "changes mandatory step body")

    def test_workspace_test_failure_and_serial_environment_are_mandatory(self) -> None:
        for field, value in (("if", "false"), ("continue-on-error", "true"), ("shell", "bash {0}")):
            changed = copy.deepcopy(LIVE)
            changed["jobs"]["workspace-tests"]["steps"][-1][field] = value
            with self.subTest(field=field):
                self.rejected(changed, "required CI workspace test evidence")
        for field in ("RUST_TEST_THREADS", "CARGO_BUILD_JOBS", "RUSTFLAGS"):
            changed = copy.deepcopy(LIVE)
            del changed["jobs"]["workspace-tests"]["steps"][-1]["env"][field]
            with self.subTest(environment=field):
                self.rejected(changed, "changes mandatory step shape")

    def test_every_prerequisite_is_required_and_cannot_silently_skip(self) -> None:
        steps = LIVE["jobs"]["workspace-tests"]["steps"]
        for index in range(len(steps) - 1):
            for mutation in ("remove", "if", "continue-on-error", "replace"):
                changed = copy.deepcopy(LIVE)
                changed_steps = changed["jobs"]["workspace-tests"]["steps"]
                if mutation == "remove":
                    changed_steps.pop(index)
                elif mutation == "replace":
                    key = "uses" if "uses" in changed_steps[index] else "run"
                    changed_steps[index][key] = "true"
                else:
                    changed_steps[index][mutation] = "true"
                with self.subTest(index=index, mutation=mutation):
                    self.rejected(changed, "exact prerequisite steps or fixture adjacency")

    def test_native_fixture_cannot_move_after_the_tests(self) -> None:
        changed = copy.deepcopy(LIVE)
        steps = changed["jobs"]["workspace-tests"]["steps"]
        steps[-1], steps[-2] = steps[-2], steps[-1]
        self.rejected(changed, "exact prerequisite steps or fixture adjacency")


if __name__ == "__main__":
    unittest.main()

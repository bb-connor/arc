#!/usr/bin/env python3
"""Exercise the required aggregate and the unchanged workspace and market suite prerequisites."""

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
CHILDREN = ("build-lint", "workspace-tests", "cognition-market")
PRODUCERS = (*CHILDREN, "msrv-workspace")
MARKET_STEP = "cognition-market promoted-default build, clippy, and tests"


class WorkspaceCiExtractionTests(unittest.TestCase):
    def rejected(self, changed: dict, message: str) -> None:
        with self.assertRaisesRegex(CHECKER.ContractError, message):
            CHECKER.validate_build_lint_test(changed)

    def test_live_workflow_preserves_required_aggregate(self) -> None:
        CHECKER.validate_build_lint_test(LIVE)

    def aggregate_passes(self, job: str, docs_only: str, results: dict[str, str]) -> bool:
        command = LIVE["jobs"][job]["steps"][0]["run"].replace(
            "${{ needs.classify.outputs.docs_only }}", docs_only
        )
        for dependency, result in results.items():
            command = command.replace(f"${{{{ needs.{dependency}.result }}}}", result)
        self.assertNotIn("${{", command)
        return subprocess.run(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", command],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        ).returncode == 0

    def test_aggregates_accept_only_full_runs_or_classified_documentation(self) -> None:
        states = ("success", "failure", "skipped", "")
        for job, children, gates in (
            ("check", CHILDREN, ("docs-gates",)),
            ("msrv", ("msrv-workspace",), ()),
        ):
            for docs_only, classify, results in itertools.product(
                ("true", "false", ""),
                ("success", "failure"),
                itertools.product(states, repeat=len(children) + len(gates)),
            ):
                gate_results, child_results = results[:len(gates)], results[len(gates):]
                if docs_only == "true":
                    expected = set(gate_results) <= {"success"} and set(child_results) == {"skipped"}
                else:
                    expected = set(gate_results) <= {"skipped"} and set(child_results) == {"success"}
                with self.subTest(job=job, docs_only=docs_only, classify=classify, results=results):
                    self.assertEqual(
                        self.aggregate_passes(
                            job,
                            docs_only,
                            {"classify": classify, **dict(zip((*gates, *children), results))},
                        ),
                        expected and classify == "success",
                    )

    def test_aggregate_refuses_missing_dependencies_or_final_evaluation(self) -> None:
        for key in ("needs", "if", "steps"):
            changed = copy.deepcopy(LIVE)
            del changed["jobs"]["check"][key]
            with self.subTest(key=key):
                self.rejected(changed, "exact fail-closed body")
        for child in CHILDREN:
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
        for child in CHILDREN:
            changed = copy.deepcopy(LIVE)
            changed["jobs"][child]["name"] = "Build, lint, test"
            with self.subTest(child=child):
                self.rejected(changed, "exact unique aggregate")

    def test_children_skip_only_for_classified_documentation(self) -> None:
        for child, field in itertools.product(
            PRODUCERS,
            ("if", "continue-on-error", "strategy", "needs", "env", "container"),
        ):
            changed = copy.deepcopy(LIVE)
            changed["jobs"][child][field] = "false"
            with self.subTest(child=child, field=field):
                self.rejected(changed, "changes its execution contract")

    def test_children_keep_host_and_original_budget(self) -> None:
        for child, (field, value) in itertools.product(
            PRODUCERS,
            (("runs-on", "windows-latest"), ("timeout-minutes", "361")),
        ):
            changed = copy.deepcopy(LIVE)
            changed["jobs"][child][field] = value
            with self.subTest(child=child, field=field):
                self.rejected(changed, "changes its execution contract")

    def test_classifier_and_documentation_gates_are_exact(self) -> None:
        for job, path, value, message in (
            ("msrv", ("if",), "${{ success() }}", "MSRV build and test changes"),
            ("msrv", ("needs",), ["classify"], "MSRV build and test changes"),
            ("classify", ("steps", 1, "run"), "echo docs_only=true", "classifier job changed"),
            ("classify", ("steps", 0, "with", "fetch-depth"), "1", "classifier job changed"),
            ("classify", ("continue-on-error",), "true", "classifier job changed"),
            ("docs-gates", ("if",), "${{ always() }}", "documentation gates job"),
            ("docs-gates", ("steps", -1, "run"), "true", "documentation-only content gates"),
            ("docs-gates", ("steps", -1, "if"), "false", "documentation-only content gates"),
        ):
            changed = copy.deepcopy(LIVE)
            target = changed["jobs"][job]
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            with self.subTest(job=job, path=path):
                self.rejected(changed, message)

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

    def market_step(self, changed: dict) -> dict:
        return changed["jobs"]["cognition-market"]["steps"][-1]

    def test_market_command_cannot_filter_or_drop_suites(self) -> None:
        for old, new in (
            ("cargo test -p chio-store-sqlite\n", ""),
            ("cargo test -p chio-control-plane --lib", "cargo test -p chio-control-plane --lib -- --skip security"),
            ("-- -D warnings", ""),
            ("umask 022\n", ""),
        ):
            changed = copy.deepcopy(LIVE)
            step = self.market_step(changed)
            step["run"] = step["run"].replace(old, new)
            with self.subTest(replacement=old):
                self.rejected(changed, "changes mandatory step body")

    def test_market_failure_and_serial_environment_are_mandatory(self) -> None:
        for field, value in (("if", "false"), ("continue-on-error", "true"), ("shell", "bash {0}")):
            changed = copy.deepcopy(LIVE)
            self.market_step(changed)[field] = value
            with self.subTest(field=field):
                self.rejected(changed, "required CI cognition market evidence")
        for field in ("RUST_TEST_THREADS", "CARGO_BUILD_JOBS", "RUSTFLAGS"):
            changed = copy.deepcopy(LIVE)
            del self.market_step(changed)["env"][field]
            with self.subTest(environment=field):
                self.rejected(changed, "changes mandatory step shape")
        changed = copy.deepcopy(LIVE)
        self.market_step(changed)["env"]["RUST_TEST_THREADS"] = "2"
        self.rejected(changed, "changes mandatory step shape")

    def test_every_market_prerequisite_is_required_and_cannot_silently_skip(self) -> None:
        steps = LIVE["jobs"]["cognition-market"]["steps"]
        self.assertEqual(len(steps), len(CHECKER.EXPECTED_COGNITION_MARKET_SETUP) + 1)
        for index in range(len(steps) - 1):
            for mutation in ("remove", "if", "continue-on-error", "replace"):
                changed = copy.deepcopy(LIVE)
                changed_steps = changed["jobs"]["cognition-market"]["steps"]
                if mutation == "remove":
                    changed_steps.pop(index)
                elif mutation == "replace":
                    key = "uses" if "uses" in changed_steps[index] else "run"
                    changed_steps[index][key] = "true"
                else:
                    changed_steps[index][mutation] = "true"
                with self.subTest(index=index, mutation=mutation):
                    self.rejected(changed, "cognition-market changes its exact prerequisite steps")

    def test_market_prerequisites_cannot_gain_or_reorder_steps(self) -> None:
        fixture = next(
            step for step in LIVE["jobs"]["workspace-tests"]["steps"]
            if step.get("uses") == "./.github/actions/enforced-native-fixture"
        )
        changed = copy.deepcopy(LIVE)
        changed["jobs"]["cognition-market"]["steps"].insert(-1, copy.deepcopy(fixture))
        self.rejected(changed, "cognition-market changes its exact prerequisite steps")
        changed = copy.deepcopy(LIVE)
        steps = changed["jobs"]["cognition-market"]["steps"]
        steps[-1], steps[-2] = steps[-2], steps[-1]
        self.rejected(changed, "cognition-market changes its exact prerequisite steps")

    def test_market_suite_cannot_reappear_in_another_job(self) -> None:
        market = LIVE["jobs"]["cognition-market"]["steps"][-1]
        for child in ("build-lint", "msrv-workspace"):
            changed = copy.deepcopy(LIVE)
            changed["jobs"][child]["steps"].append(copy.deepcopy(market))
            with self.subTest(child=child):
                self.rejected(changed, "must run only in cognition-market")
        changed = copy.deepcopy(LIVE)
        renamed = {**copy.deepcopy(market), "name": "Promoted market"}
        changed["jobs"]["build-lint"]["steps"].append(renamed)
        self.rejected(changed, "must run only in cognition-market")

    def test_native_fixture_cannot_move_after_the_tests(self) -> None:
        changed = copy.deepcopy(LIVE)
        steps = changed["jobs"]["workspace-tests"]["steps"]
        steps[-1], steps[-2] = steps[-2], steps[-1]
        self.rejected(changed, "exact prerequisite steps or fixture adjacency")


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Refusal controls for the pheromone fixture-gate workflow contract."""

from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("pheromone_ci", ROOT / "scripts/check-pheromone-ci.py")
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load pheromone CI checker")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

LIVE = CHECKER.load_workflows(ROOT)
FACETS = CHECKER.known_facets(ROOT)
PINNED = "chio-pheromone-pinned.yml"
COMPOSITE = "chio-pheromone-composite.yml"


def job(workflows: dict, file: str) -> dict:
    return workflows[file]["jobs"][CHECKER.GROUPS[file][1]]


def gate_index(workflows: dict, facet: str) -> tuple[str, int]:
    for file in CHECKER.GROUPS:
        for index, step in enumerate(job(workflows, file)["steps"]):
            if step.get("run") == f"cargo xtask check fixtures {facet}":
                return file, index
    raise AssertionError(facet)


class PheromoneCiTests(unittest.TestCase):
    def rejected(self, workflows: dict, message: str) -> None:
        with self.assertRaisesRegex(CHECKER.ContractError, message):
            CHECKER.validate_documents(workflows, FACETS)

    def test_live_workflows_cover_every_facet_once(self) -> None:
        CHECKER.validate(ROOT)

    def test_every_missing_gate_is_refused(self) -> None:
        for facet in FACETS:
            changed = copy.deepcopy(LIVE)
            file, index = gate_index(changed, facet)
            del job(changed, file)["steps"][index]
            with self.subTest(facet=facet):
                self.rejected(changed, f"facet {facet} must run exactly once")

    def test_duplicate_gates_are_refused(self) -> None:
        for facet in FACETS:
            changed = copy.deepcopy(LIVE)
            file, index = gate_index(changed, facet)
            step = copy.deepcopy(job(changed, file)["steps"][index])
            other = COMPOSITE if file == PINNED else PINNED
            job(changed, other)["steps"].append(step)
            with self.subTest(facet=facet):
                self.rejected(changed, f"facet {facet} must run exactly once")
        changed = copy.deepcopy(LIVE)
        changed["ci.yml"] = {"jobs": {"stray": {"steps": [{"run": "cargo xtask check fixtures relay"}]}}}
        self.rejected(changed, "facet relay must run exactly once")

    def test_gate_steps_cannot_suppress_or_tolerate_failure(self) -> None:
        mutations = (
            ("if", "${{ success() }}"),
            ("if", "${{ always() }}"),
            ("continue-on-error", True),
            ("env", {"CARGO_INCREMENTAL": "1"}),
            ("working-directory", "xtask"),
            ("run", "cargo xtask check fixtures relay --schema-only"),
            ("name", "Renamed gate"),
        )
        for facet in FACETS:
            for key, value in mutations:
                changed = copy.deepcopy(LIVE)
                file, index = gate_index(changed, facet)
                step = job(changed, file)["steps"][index]
                if key == "run":
                    step["run"] = f"cargo xtask check fixtures {facet} --schema-only"
                else:
                    step[key] = value
                with self.subTest(facet=facet, key=key):
                    self.rejected(changed, "facet gate steps changed")
            changed = copy.deepcopy(LIVE)
            file, index = gate_index(changed, facet)
            del job(changed, file)["steps"][index]["if"]
            with self.subTest(facet=facet, key="if removed"):
                self.rejected(changed, "facet gate steps changed")

    def test_facets_cannot_move_between_groups(self) -> None:
        changed = copy.deepcopy(LIVE)
        file, index = gate_index(changed, "relay-alert-routing")
        step = job(changed, file)["steps"].pop(index)
        job(changed, PINNED)["steps"].append(step)
        self.rejected(changed, "facet gate steps changed")

    def test_every_prerequisite_is_required(self) -> None:
        for file, (_, _, _, prefix, _) in CHECKER.GROUPS.items():
            for index in range(len(prefix)):
                for mutation in ("remove", "if", "continue-on-error", "replace"):
                    changed = copy.deepcopy(LIVE)
                    steps = job(changed, file)["steps"]
                    if mutation == "remove":
                        steps.pop(index)
                    elif mutation == "replace":
                        key = "uses" if "uses" in steps[index] else "run"
                        steps[index][key] = "true"
                    else:
                        steps[index][mutation] = "false"
                    with self.subTest(file=file, index=index, mutation=mutation):
                        self.rejected(changed, "setup prerequisites changed")

    def test_node_and_toolchain_inputs_are_pinned(self) -> None:
        for file, index, key, value in (
            (PINNED, 3, "node-version", "24"),
            (COMPOSITE, 2, "node-version", "22"),
            (COMPOSITE, 1, "toolchain", "1.95.0"),
        ):
            changed = copy.deepcopy(LIVE)
            job(changed, file)["steps"][index]["with"][key] = value
            with self.subTest(file=file, key=key):
                self.rejected(changed, "setup prerequisites changed")

    def test_every_trigger_path_is_required(self) -> None:
        for file in CHECKER.GROUPS:
            for event in ("pull_request", "push"):
                for path in LIVE[file][True][event]["paths"]:
                    changed = copy.deepcopy(LIVE)
                    changed[file][True][event]["paths"].remove(path)
                    with self.subTest(file=file, event=event, path=path):
                        self.rejected(changed, "trigger events, branches or paths changed")
            changed = copy.deepcopy(LIVE)
            changed[file][True]["push"]["branches"] = ["main", "release/*"]
            self.rejected(changed, "trigger events, branches or paths changed")

    def test_token_scope_job_shape_and_concurrency_are_pinned(self) -> None:
        for file in CHECKER.GROUPS:
            for label, mutate, message in (
                ("permissions", lambda w: w[file].update(permissions={"contents": "write"}), "token permissions"),
                ("runner", lambda w: job(w, file).update({"runs-on": "self-hosted"}), "job shape"),
                ("tolerated job", lambda w: job(w, file).update({"continue-on-error": True}), "job shape"),
                ("concurrency", lambda w: job(w, file)["concurrency"].update(group="shared"), "job shape"),
            ):
                changed = copy.deepcopy(LIVE)
                mutate(changed)
                with self.subTest(file=file, label=label):
                    self.rejected(changed, message)

    def test_per_facet_workflow_files_are_refused(self) -> None:
        changed = copy.deepcopy(LIVE)
        changed["chio-pheromone-relay.yml"] = {"jobs": {}}
        self.rejected(changed, "per-facet pheromone workflow file is present")


if __name__ == "__main__":
    unittest.main()

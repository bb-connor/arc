#!/usr/bin/env python3
"""Exercise publication currency against regenerated test merges with offline APIs.

Every case runs the real capture, finalizer and attestation shell from the
workflow definitions through the offline API fakes of the landing regression
suite. Original cases describe behaviour the current producers refuse and the
currency rules require; preservation cases pin refusals and denials that must
hold before and after those rules.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import re
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
LANDING_SPEC = importlib.util.spec_from_file_location(
    "trusted_ci_landing_regressions", ROOT / "scripts/tests/trusted-ci-landing-regressions.test.py"
)
if LANDING_SPEC is None or LANDING_SPEC.loader is None:
    raise RuntimeError("cannot load the landing regression harness")
LANDING = importlib.util.module_from_spec(LANDING_SPEC)
sys.modules[LANDING_SPEC.name] = LANDING
LANDING_SPEC.loader.exec_module(LANDING)

REPOSITORY, PR, SOURCE, DEFINITION = LANDING.REPOSITORY, LANDING.PR, LANDING.SOURCE, LANDING.DEFINITION
PREFIX = f"repos/{REPOSITORY}"

# Observed test-merge regeneration in the scratch repository (pull request #12,
# c9-m-regeneration): refs/pull/12/merge moved 431bd0fe -> 8e280a3f -> 125f0b53
# while main, the head, both parents and the tree stayed the same.
C9_BASE, C9_HEAD, C9_TREE = (
    "35987ff31972277a0a062e7a3f2bdaafa75ea938", "6aa9248cbb25c1aa87c35ab4291b3e04da906ab8",
    "50c10956584f514238d6b48a54b164e6f538e30d",
)
C9_MERGE_A, C9_MERGE_B, C9_MERGE_C = (
    "431bd0fea0ef5d9e2c47a36228bcc7937aaa39b8", "8e280a3f86e88ff5337520c1ee61eaf881c65ca2",
    "125f0b53ef97e5dc5e3247d484b5fe53191919ba",
)
C9_REGENERATIONS = (C9_MERGE_A, C9_MERGE_B, C9_MERGE_C)

# The bash ERR trap reports the producer command that refused, so a refusal can
# be attributed to an exact check rather than to any failure.
REFUSAL_TRACE = "set -E\ntrap 'printf \"refused-at: %s\\n\" \"${BASH_COMMAND}\" >&2' ERR\n"
EXPRESSION = re.compile(r"\$\{\{ ([A-Za-z0-9_.-]+) \}\}")


def refusal(run) -> str:
    lines = [line[len("refused-at: "):] for line in run.result.stderr.splitlines() if line.startswith("refused-at: ")]
    return lines[0] if lines else ""


def step_definition(name: str, job: str, step: str) -> tuple[dict, dict]:
    job_definition = LANDING.workflow(name)["jobs"][job]
    matches = [item for item in job_definition["steps"] if item.get("name") == step]
    if len(matches) != 1:
        raise AssertionError(f"{name} {job} has {len(matches)} steps named {step!r}")
    return job_definition, matches[0]


def render_step(name: str, job: str, step: str, context: dict[str, str]) -> tuple[str, dict[str, str]]:
    """Return the step script and the environment its own `env:` wiring resolves to."""
    job_definition, step_definition_ = step_definition(name, job, step)
    environment = {}
    for key, expression in (job_definition.get("env", {}) | step_definition_.get("env", {})).items():
        match = EXPRESSION.fullmatch(expression)
        if match is None or match.group(1) not in context:
            raise AssertionError(f"{step}: no offline value for {key}: {expression}")
        environment[key] = context[match.group(1)]

    def inline(match: re.Match) -> str:
        if match.group(1) not in context:
            raise AssertionError(f"{step}: no offline value for inline {match.group(0)}")
        return context[match.group(1)]

    script = EXPRESSION.sub(inline, step_definition_["run"])
    if "${{" in script:
        raise AssertionError(f"{step}: unresolved workflow expression")
    return script, environment


def outputs(run) -> dict[str, str]:
    return dict(line.split("=", 1) for line in run.output.splitlines())


def commit_shape(data: dict, sha: str) -> tuple[list[str], str]:
    record = data[f"{PREFIX}/git/commits/{sha}"]
    return [parent["sha"] for parent in record["parents"]], record["tree"]["sha"]


def merge_ref_get(number: int = PR) -> str:
    return f"GET {PREFIX}/git/ref/pull/{number}/merge"


def committed_evidence_records(head: str) -> dict:
    """The evidence commit on the authorized source, as the REST commit and tree APIs return it."""
    names = ("enterprise-migration-binding-digest.txt", "enterprise-migration-canary.json",
             "enterprise-migration-canary.json.sha256")
    data = {
        f"{PREFIX}/commits/{head}": {"sha": head, "parents": [{"sha": SOURCE}], "files": [
            {"filename": f"audits/evidence/enterprise-linux/{name}", "status": "modified"} for name in names]},
        f"{PREFIX}/git/commits/{head}": {"sha": head, "parents": [{"sha": SOURCE}], "tree": {"sha": "e0" * 20}},
    }
    for parent, component, child in (("e0", "audits", "e1"), ("e1", "evidence", "e2"), ("e2", "enterprise-linux", "e3")):
        data[f"{PREFIX}/git/trees/{parent * 20}"] = {"sha": parent * 20, "truncated": False, "tree": [
            {"path": component, "mode": "040000", "type": "tree", "sha": child * 20}]}
    data[f"{PREFIX}/git/trees/{'e3' * 20}"] = {"sha": "e3" * 20, "truncated": False, "tree": [
        {"path": name, "mode": "100644", "type": "blob", "sha": "f" * 40} for name in names]}
    return data


def regeneration_tuple(live_merge: str, stable_merge: str | None = None, *, main: str = C9_BASE) -> dict:
    """The c9 tuple with the capture merge recorded as C9_MERGE_A and the live ref at `live_merge`.

    `stable_merge` is what a second read of refs/pull/N/merge returns.
    """
    data = LANDING.live_tuple(live_merge=live_merge, main=main, base=C9_BASE, head=C9_HEAD, tree=C9_TREE,
                              merges=C9_REGENERATIONS)
    data.update(committed_evidence_records(C9_HEAD))
    if stable_merge is not None:
        key = f"{PREFIX}/git/ref/pull/{PR}/merge"
        data[key] = {"__sequence": [data[key], {"ref": f"refs/pull/{PR}/merge",
                                                "object": {"type": "commit", "sha": stable_merge}}]}
    return data


def add_merge_commit(data: dict, sha: str, parents: tuple[str, str], tree: str) -> None:
    data[f"{PREFIX}/git/commits/{sha}"] = {"sha": sha, "parents": [{"sha": parent} for parent in parents],
                                           "tree": {"sha": tree}}


def authorize_capture(data: dict, recorded_merge: str = C9_MERGE_A):
    """Run the capture workflow's live merge revalidation step for the c9 tuple."""
    now = int(time.time())
    capture = {
        "capture_actor": "bb-connor", "capture_blob_sha": "6" * 40, "capture_created_epoch": str(now - 60),
        "capture_run_attempt": "1", "capture_run_id": "401", "capture_workflow_id": "105",
        "base_ref": "main", "base_repository": REPOSITORY, "base_sha": C9_BASE,
        "controller_actor": "bb-connor", "controller_blob_sha": "6" * 40,
        "controller_issued_at_unix_ms": str((now - 120) * 1000), "controller_run_attempt": "1",
        "controller_run_id": "111", "controller_workflow_id": "104",
        "labels_digest": hashlib.sha256(b"[]").hexdigest(), "merge_commit_sha": recorded_merge,
        "merge_tree_sha": C9_TREE, "mode": "enforcement", "pr_number": str(PR),
        "security_definition_sha": DEFINITION, "source_repository": REPOSITORY, "source_sha": C9_HEAD,
    }
    context = {f"steps.authenticate.outputs.{key}": value for key, value in capture.items()} | {
        "vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA": SOURCE,
        "vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA": DEFINITION,
        "github.token": LANDING.ACTIONS_TOKEN,
    }
    script, environment = render_step("enterprise-linux-capture.yml", "authorize-capture",
                                      "Revalidate live merge authorization", context)
    return LANDING.run_offline_step(REFUSAL_TRACE + script, data, environment)


class CaptureAuthorizationRegenerationOriginalTests(unittest.TestCase):
    """Original (RED at e82ee26673, turns GREEN when P4 lands): C-P4-2.

    The capture workflow's `Revalidate live merge authorization` step compares
    the live refs/pull/N/merge SHA with the recorded test merge at both reads
    (CAP:531 and CAP:639). A test merge that GitHub regenerated with the
    recorded parents and tree must authorize the capture, and the step must keep
    recording the capture-time merge.
    """

    def test_capture_authorizes_a_regenerated_live_merge_with_the_recorded_parents_and_tree(self) -> None:
        control = authorize_capture(regeneration_tuple(C9_MERGE_A))
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertEqual(control.calls.count(merge_ref_get()), 2)
        self.assertEqual({key: outputs(control)[key] for key in ("base_sha", "merge_commit_sha", "merge_tree_sha", "source_sha")},
                         {"base_sha": C9_BASE, "merge_commit_sha": C9_MERGE_A, "merge_tree_sha": C9_TREE,
                          "source_sha": C9_HEAD})
        for label, live, stable in (("regenerated before the first read", C9_MERGE_B, C9_MERGE_B),
                                    ("regenerated between the two reads", C9_MERGE_A, C9_MERGE_B),
                                    ("regenerated twice", C9_MERGE_B, C9_MERGE_C)):
            with self.subTest(case=label):
                data = regeneration_tuple(live, stable)
                for merge in {live, stable}:
                    self.assertEqual(commit_shape(data, merge), ([C9_BASE, C9_HEAD], C9_TREE))
                run = authorize_capture(data)
                self.assertNotIn("unprovided API", run.result.stderr)
                self.assertIn(merge_ref_get(), run.calls)
                if live == C9_MERGE_A:
                    self.assertEqual(run.calls.count(merge_ref_get()), 2)
                self.assertEqual(run.result.returncode, 0,
                                 f"capture authorization recorded {C9_MERGE_A} and refused live test merges {live} then "
                                 f"{stable}, which have the recorded parents [{C9_BASE}, {C9_HEAD}] and tree {C9_TREE} "
                                 f"(refused at: {refusal(run)})")
                self.assertEqual(run.calls.count(merge_ref_get()), 2)
                self.assertIn(f"GET {PREFIX}/git/commits/{C9_MERGE_A}", run.calls)
                self.assertIn(f"GET {PREFIX}/git/commits/{stable}", run.calls)
                self.assertEqual(outputs(run)["merge_commit_sha"], C9_MERGE_A)


if __name__ == "__main__":
    unittest.main()

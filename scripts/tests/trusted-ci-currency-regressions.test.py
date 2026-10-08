#!/usr/bin/env python3
"""Exercise publication currency against regenerated test merges with offline APIs.

Every case runs the real capture, finalizer and attestation shell from the
workflow definitions through the offline API fakes of the landing regression
suite. Original cases describe behaviour the current producers refuse and the
currency rules require; preservation cases pin refusals and denials that must
hold before and after those rules.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import io
import json
import re
import sys
import time
import unittest
import unittest.mock
import urllib.parse
import zipfile
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

# Observed in the scratch repository (pull request #12): refs/pull/12/merge was
# regenerated from 431bd0fe to 8e280a3f to 125f0b53 while main, the head, both
# parents and the tree stayed the same.
REGEN_BASE, REGEN_HEAD, REGEN_TREE = (
    "35987ff31972277a0a062e7a3f2bdaafa75ea938", "6aa9248cbb25c1aa87c35ab4291b3e04da906ab8",
    "50c10956584f514238d6b48a54b164e6f538e30d",
)
CAPTURE_MERGE, REGENERATED_ONCE, REGENERATED_TWICE = (
    "431bd0fea0ef5d9e2c47a36228bcc7937aaa39b8", "8e280a3f86e88ff5337520c1ee61eaf881c65ca2",
    "125f0b53ef97e5dc5e3247d484b5fe53191919ba",
)
REGENERATIONS = (CAPTURE_MERGE, REGENERATED_ONCE, REGENERATED_TWICE)

# The bash ERR trap reports the producer command that refused, so a refusal can
# be attributed to an exact check rather than to any failure.
REFUSAL_TRACE = "set -E\ntrap 'printf \"refused-at: %s\\n\" \"${BASH_COMMAND}\" >&2' ERR\n"
EXPRESSION = re.compile(r"\$\{\{ ([A-Za-z0-9_.-]+) \}\}")
GITHUB_CONTEXT = {
    "github.repository": REPOSITORY, "github.repository_owner": "bb-connor", "github.repository_id": "1195888645",
    "github.repository_owner_id": "1", "github.event.repository.default_branch": "main",
}


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
    context = GITHUB_CONTEXT | context
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


def regeneration_tuple(live_merge: str, stable_merge: str | None = None, *, main: str = REGEN_BASE) -> dict:
    """The observed tuple with refs/pull/N/merge at `live_merge`, then at `stable_merge` on a second read."""
    data = LANDING.live_tuple(live_merge=live_merge, main=main, base=REGEN_BASE, head=REGEN_HEAD, tree=REGEN_TREE,
                              merges=REGENERATIONS)
    data.update(committed_evidence_records(REGEN_HEAD))
    if stable_merge is not None:
        key = f"{PREFIX}/git/ref/pull/{PR}/merge"
        data[key] = {"__sequence": [data[key], {"ref": f"refs/pull/{PR}/merge",
                                                "object": {"type": "commit", "sha": stable_merge}}]}
    return data


def add_merge_commit(data: dict, sha: str, parents: tuple[str, str], tree: str) -> None:
    data[f"{PREFIX}/git/commits/{sha}"] = {"sha": sha, "parents": [{"sha": parent} for parent in parents],
                                           "tree": {"sha": tree}}


def authorize_capture(data: dict, recorded_merge: str = CAPTURE_MERGE):
    """Run the capture workflow's live merge revalidation for the observed tuple, recorded at `recorded_merge`."""
    now = int(time.time())
    capture = {
        "capture_actor": "bb-connor", "capture_blob_sha": "6" * 40, "capture_created_epoch": str(now - 60),
        "capture_run_attempt": "1", "capture_run_id": "401", "capture_workflow_id": "105",
        "base_ref": "main", "base_repository": REPOSITORY, "base_sha": REGEN_BASE,
        "controller_actor": "bb-connor", "controller_blob_sha": "6" * 40,
        "controller_issued_at_unix_ms": str((now - 120) * 1000), "controller_run_attempt": "1",
        "controller_run_id": "111", "controller_workflow_id": "104",
        "labels_digest": hashlib.sha256(b"[]").hexdigest(), "merge_commit_sha": recorded_merge,
        "merge_tree_sha": REGEN_TREE, "mode": "enforcement", "pr_number": str(PR),
        "security_definition_sha": DEFINITION, "source_repository": REPOSITORY, "source_sha": REGEN_HEAD,
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
    """Original (RED at e82ee26673, turns GREEN when P4 lands).

    A live test merge that GitHub regenerated with the recorded parents and
    tree authorizes the capture at both reads of refs/pull/N/merge in
    `Revalidate live merge authorization`, and the step still records and
    checks the capture-time merge.
    """

    def test_capture_authorizes_a_regenerated_live_merge_with_the_recorded_parents_and_tree(self) -> None:
        control = authorize_capture(regeneration_tuple(CAPTURE_MERGE))
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertEqual(control.calls.count(merge_ref_get()), 2)
        self.assertEqual({key: outputs(control)[key] for key in ("base_sha", "merge_commit_sha", "merge_tree_sha", "source_sha")},
                         {"base_sha": REGEN_BASE, "merge_commit_sha": CAPTURE_MERGE, "merge_tree_sha": REGEN_TREE,
                          "source_sha": REGEN_HEAD})
        for label, live, stable in (("regenerated before the first read", REGENERATED_ONCE, REGENERATED_ONCE),
                                    ("regenerated between the two reads", CAPTURE_MERGE, REGENERATED_ONCE),
                                    ("regenerated twice", REGENERATED_ONCE, REGENERATED_TWICE)):
            with self.subTest(case=label):
                data = regeneration_tuple(live, stable)
                for merge in {live, stable}:
                    self.assertEqual(commit_shape(data, merge), ([REGEN_BASE, REGEN_HEAD], REGEN_TREE))
                run = authorize_capture(data)
                self.assertNotIn("unprovided API", run.result.stderr)
                self.assertIn(merge_ref_get(), run.calls)
                if live == CAPTURE_MERGE:
                    self.assertEqual(run.calls.count(merge_ref_get()), 2)
                self.assertEqual(run.result.returncode, 0,
                                 f"capture authorization recorded {CAPTURE_MERGE} and refused live test merges {live} then "
                                 f"{stable}, which have the recorded parents [{REGEN_BASE}, {REGEN_HEAD}] and tree {REGEN_TREE} "
                                 f"(refused at: {refusal(run)})")
                self.assertEqual(run.calls.count(merge_ref_get()), 2)
                self.assertIn(f"GET {PREFIX}/git/commits/{CAPTURE_MERGE}", run.calls)
                self.assertIn(f"GET {PREFIX}/git/commits/{stable}", run.calls)
                self.assertEqual(outputs(run)["merge_commit_sha"], CAPTURE_MERGE)


def controller_records(issued: int) -> dict:
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(issued))
    return {
        f"{PREFIX}/actions/workflows/enterprise-evidence-controller.yml": {
            "id": 104, "path": ".github/workflows/enterprise-evidence-controller.yml", "state": "active"},
        f"{PREFIX}/actions/runs/111": {
            "id": 111, "workflow_id": 104, "path": ".github/workflows/enterprise-evidence-controller.yml",
            "event": "pull_request_target", "status": "completed", "conclusion": "success",
            "head_sha": DEFINITION, "head_branch": "main", "run_attempt": 1,
            "actor": {"login": "bb-connor"}, "triggering_actor": {"login": "bb-connor"}, "created_at": created_at},
        f"{PREFIX}/contents/.github/workflows/enterprise-evidence-controller.yml?ref={DEFINITION}": {"sha": "6" * 40},
    }


def validate_capture(data: dict, recorded_merge: str = CAPTURE_MERGE):
    """Run the finalizer's capture revalidation for the observed tuple, recorded at `recorded_merge`."""
    issued = int(time.time()) - 120
    validated = {
        "authorized_source_sha": SOURCE, "base_ref": "main", "base_repository": REPOSITORY, "base_sha": REGEN_BASE,
        "capture_issued_at_unix_ms": str((issued + 60) * 1000), "capture_run_attempt": "1", "capture_run_id": "401",
        "controller_actor": "bb-connor", "controller_definition_blob": "6" * 40,
        "controller_issued_at_unix_ms": str(issued * 1000), "controller_run_attempt": "1", "controller_run_id": "111",
        "controller_workflow_id": "104", "labels_digest": hashlib.sha256(b"[]").hexdigest(),
        "merge_commit_sha": recorded_merge, "merge_tree_sha": REGEN_TREE, "pr_number": str(PR),
        "security_definition_sha": DEFINITION, "source_repository": REPOSITORY, "source_sha": REGEN_HEAD,
    }
    context = {f"steps.validate.outputs.{key}": value for key, value in validated.items()} | {
        "vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA": SOURCE,
        "vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA": DEFINITION,
        "github.token": LANDING.ACTIONS_TOKEN, "github.event.repository.default_branch": "main",
    }
    script, environment = render_step("enterprise-evidence-finalizer.yml", "validate-capture",
                                      "Revalidate live authorization and issuance freshness", context)
    return LANDING.run_offline_step(REFUSAL_TRACE + script, data | controller_records(issued), environment)


class FinalizerCaptureRegenerationOriginalTests(unittest.TestCase):
    """Original (RED at e82ee26673, turns GREEN when P4 lands).

    A live test merge that GitHub regenerated with the recorded parents and
    tree passes the finalizer's `Revalidate live authorization and issuance
    freshness`, which still checks the recorded capture merge and that main is
    the recorded base.
    """

    def test_capture_validation_accepts_a_regenerated_live_merge_with_the_recorded_parents_and_tree(self) -> None:
        tree_walk_end = f"GET {PREFIX}/git/trees/{'e3' * 20}"
        control = validate_capture(regeneration_tuple(CAPTURE_MERGE))
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertIn(tree_walk_end, control.calls)
        for live in (REGENERATED_ONCE, REGENERATED_TWICE):
            with self.subTest(live_merge=live):
                data = regeneration_tuple(live)
                self.assertEqual(commit_shape(data, live), ([REGEN_BASE, REGEN_HEAD], REGEN_TREE))
                run = validate_capture(data)
                self.assertNotIn("unprovided API", run.result.stderr)
                self.assertIn(merge_ref_get(), run.calls)
                self.assertEqual(run.result.returncode, 0,
                                 f"capture validation recorded {CAPTURE_MERGE} and refused live test merge {live}, which "
                                 f"has the recorded parents [{REGEN_BASE}, {REGEN_HEAD}] and tree {REGEN_TREE} "
                                 f"(refused at: {refusal(run)})")
                for read in (f"git/commits/{live}", f"git/commits/{CAPTURE_MERGE}", "git/ref/heads/main"):
                    self.assertIn(f"GET {PREFIX}/{read}", run.calls)
                self.assertIn(tree_walk_end, run.calls)


def authenticate_ci_step(data: dict, *, recorded_merge: str = LANDING.MERGE):
    """Run `Authenticate exact successful current CI run` with its own env wiring and a one-poll budget."""
    context = {
        "needs.validate-capture.outputs.base_ref": "main", "needs.validate-capture.outputs.base_sha": LANDING.BASE,
        "needs.validate-capture.outputs.merge_commit_sha": recorded_merge,
        "needs.validate-capture.outputs.merge_tree_sha": LANDING.TREE,
        "steps.bind.outputs.ci_workflow_id": str(LANDING.CI_WORKFLOW),
        "steps.bind.outputs.evidence_sha": LANDING.EVIDENCE, "steps.bind.outputs.head_ref": LANDING.HEAD_REF,
        "steps.bind.outputs.pr_number": str(PR), "github.token": LANDING.ACTIONS_TOKEN,
    }
    script, environment = render_step("enterprise-evidence-finalizer.yml", "authorize-security-check-publication",
                                      "Authenticate exact successful current CI run", context)
    return LANDING.run_offline_step(REFUSAL_TRACE + script, data, environment, poll_limit=True)


CI_HISTORY_GET = f"GET {PREFIX}/{LANDING.CI_HISTORY_QUERY}"


def polls(run) -> list[str]:
    return [call for call in run.calls if call.startswith("sleep ")]


# Test merges that are not the recorded tuple: one with another tree, and one
# over another evidence head or an unrelated commit.
OTHER_TREE_MERGE, OTHER_HEAD_MERGE = "4d" * 20, "5e" * 20
OTHER_TREE = "6f" * 20


class CiRunMergeIdentityOriginalTests(unittest.TestCase):
    """Original (RED at e82ee26673, turns GREEN when P4 lands).

    `Authenticate exact successful current CI run` examines a run titled
    `CI N=<N> E=<E> B=<B> M=<M_ci>` for any test merge M_ci, and refuses it at
    once, without polling, when the M_ci commit does not have parents [B, E]
    and tree T.
    """

    def test_ci_run_titled_for_a_merge_with_other_parents_or_tree_is_refused_without_polling(self) -> None:
        control = authenticate_ci_step(LANDING.ci_authentication_fixture())
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertIn(f"ci_run_id={LANDING.CI_RUN}\n", control.output)
        for label, (sha, parents, tree) in {
            "other evidence parent [B, E']": (OTHER_HEAD_MERGE, (LANDING.BASE, LANDING.STALE_HEAD), LANDING.TREE),
            "other tree T'": (OTHER_TREE_MERGE, (LANDING.BASE, LANDING.EVIDENCE), OTHER_TREE),
        }.items():
            with self.subTest(ci_merge=label):
                data = LANDING.ci_authentication_fixture()
                LANDING.add_ci_runs(data, LANDING.pull_request_ci_run(LANDING.CI_RUN, sha))
                add_merge_commit(data, sha, parents, tree)
                listed = data[f"{PREFIX}/actions/workflows/ci.yml/runs"]["workflow_runs"]
                self.assertEqual([run["display_title"] for run in listed],
                                 [f"CI N={PR} E={LANDING.EVIDENCE} B={LANDING.BASE} M={sha}"])
                run = authenticate_ci_step(data)
                self.assertIn(CI_HISTORY_GET, run.calls)
                self.assertNotIn("unprovided API", run.result.stderr)
                self.assertEqual(polls(run), [],
                                 f"CI authentication polled instead of examining run {LANDING.CI_RUN} titled for test "
                                 f"merge {sha}, whose commit is not [B, E] with tree T")
                self.assertEqual(run.result.returncode, 1, run.result.stderr)
                self.assertIn(f"GET {PREFIX}/git/commits/{sha}", run.calls)
                self.assertEqual(run.output, "")


class CiHistoryCeilingOriginalTests(unittest.TestCase):
    """Original (RED at e82ee26673, turns GREEN when P4 lands).

    A CI history for E at the 1,000-result listing ceiling cannot be proven
    complete, so `Authenticate exact successful current CI run` refuses after
    the one filtered listing read: no unfiltered listing and no polling.
    """

    def test_ci_history_at_the_listing_ceiling_refuses_at_once(self) -> None:
        control = authenticate_ci_step(LANDING.ci_authentication_fixture())
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        for total_count in (1000, 1001, 4321):
            with self.subTest(total_count=total_count):
                data = LANDING.ci_authentication_fixture()
                first_page = [LANDING.pull_request_ci_run(LANDING.CI_RUN - offset, LANDING.MERGE)
                              for offset in range(100)]
                data[f"{PREFIX}/actions/workflows/ci.yml/runs"] = {"total_count": total_count,
                                                                  "workflow_runs": first_page}
                run = authenticate_ci_step(data)
                self.assertIn(CI_HISTORY_GET, run.calls)
                self.assertEqual(run.calls, [CI_HISTORY_GET],
                                 f"CI authentication did not refuse a history of {total_count} runs at once")
                self.assertEqual(run.result.returncode, 1, run.result.stderr)
                self.assertEqual(run.output, "")


def publish_without_stubs(data: dict):
    """Run the publisher from its revalidation helpers through its final branch, every function real."""
    body = LANDING.publisher_body()
    binding = LANDING.publication_binding()
    script = (REFUSAL_TRACE + "set -euo pipefail\nshopt -s inherit_errexit\n"
              + body[body.index("revalidate_live_publication_head() {"):])
    return LANDING.run_offline_step(script, data, LANDING.publisher_environment() | {
        "FINALIZER_RUN_ATTEMPT": "1", "FINALIZER_RUN_ID": str(LANDING.FINALIZER_RUN),
        "PUBLICATION_BINDING_DIGEST": hashlib.sha256(binding.encode()).hexdigest(),
        "publication_details_url": f"https://github.com/{REPOSITORY}/actions/runs/{LANDING.FINALIZER_RUN}/attempts/1",
    })


def listed_pull(number: int, *, state: str, head_ref: str = "evidence-copy", merge: str = LANDING.OTHER_MERGE) -> dict:
    """A pull request with head E as the list endpoints return it (no `merged` or mergeability fields)."""
    pull = LANDING.live_pull_request(number=number, merge=merge, head_ref=head_ref)
    for field in ("merged", "mergeable", "mergeable_state"):
        pull.pop(field)
    pull.update(state=state, merged_at=None, closed_at=None if state == "open" else "2026-10-08T05:40:00Z")
    return pull


def own_listing() -> dict:
    return listed_pull(PR, state="open", head_ref=LANDING.HEAD_REF, merge=LANDING.MERGE)


OPEN_LISTING, EVIDENCE_LISTING = f"{PREFIX}/pulls", f"{PREFIX}/commits/{LANDING.EVIDENCE}/pulls"
FIRST_PAGE_QUERY = {OPEN_LISTING: {"state": ["open"], "per_page": ["100"], "page": ["1"]},
                    EVIDENCE_LISTING: {"per_page": ["100"], "page": ["1"]}}


OVERSIZED_PAGE = "page exceeds 100 items"


def census_cases() -> dict[str, tuple[str, object]]:
    """Evidence-head listings that must refuse a positive boundary: a sibling, or a listing that cannot be classified."""
    own = own_listing()
    closed = listed_pull(LANDING.OTHER_PR, state="closed")
    unbounded = [copy.deepcopy(own) for _ in range(101)]
    string_number = copy.deepcopy(own) | {"number": str(PR)}
    headless = copy.deepcopy(own)
    del headless["head"]["sha"]
    short_head = copy.deepcopy(own)
    short_head["head"]["sha"] = LANDING.EVIDENCE[:12]
    return {
        "closed unmerged sibling listed only for the evidence commit": (EVIDENCE_LISTING, [own, closed]),
        "evidence commit listing is not an array": (EVIDENCE_LISTING, {"message": "Not Found", "status": "404"}),
        f"evidence commit listing {OVERSIZED_PAGE}": (EVIDENCE_LISTING, unbounded),
        "evidence commit listing item has a string number": (EVIDENCE_LISTING, [string_number]),
        "evidence commit listing item has no head sha": (EVIDENCE_LISTING, [headless]),
        "evidence commit listing item has a malformed head sha": (EVIDENCE_LISTING, [short_head]),
        "open listing is not an array": (OPEN_LISTING, {"message": "Bad credentials", "status": "401"}),
        f"open listing {OVERSIZED_PAGE}": (OPEN_LISTING, unbounded),
        "open listing item has a string number": (OPEN_LISTING, [string_number]),
        "open listing item has no head sha": (OPEN_LISTING, [headless]),
    }


def with_census(data: dict, listing: str | None = None, records: object = None) -> dict:
    data[OPEN_LISTING], data[EVIDENCE_LISTING] = [own_listing()], [own_listing()]
    if listing is not None:
        data[listing] = records
    return data


def listing_reads(run, listing: str) -> list[dict[str, list[str]]]:
    reads = []
    for call in run.calls:
        if call.startswith("GET "):
            parts = urllib.parse.urlsplit(call[len("GET "):])
            if parts.path == listing:
                reads.append(urllib.parse.parse_qs(parts.query))
    return reads


class SharedEvidenceHeadCensusOriginalTests(unittest.TestCase):
    """Original (RED at e82ee26673, turns GREEN when P4 lands).

    CI authentication and every publication boundary take a census of the pull
    requests with head E from `pulls?state=open` and `commits/E/pulls`, 100 per
    page. A listing that is not a bounded array of pull requests with a numeric
    number and a 40-hex head SHA, or that holds another number with head E in
    any state, refuses. A closed unmerged sibling appears only in
    `commits/E/pulls`.
    """

    def assert_census_fixture(self, data: dict, label: str, listing: str) -> None:
        self.assertEqual(data[OPEN_LISTING if listing == EVIDENCE_LISTING else EVIDENCE_LISTING], [own_listing()])
        if label.startswith("closed unmerged sibling"):
            sibling = data[EVIDENCE_LISTING][1]
            self.assertEqual((sibling["number"], sibling["state"], sibling["merged_at"], sibling["head"]["sha"]),
                             (LANDING.OTHER_PR, "closed", None, LANDING.EVIDENCE))
            self.assertEqual([pull["number"] for pull in data[OPEN_LISTING]], [PR])

    def test_ci_authentication_refuses_a_shared_or_unclassifiable_evidence_head(self) -> None:
        control = authenticate_ci_step(with_census(LANDING.ci_authentication_fixture()))
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertIn(f"ci_run_id={LANDING.CI_RUN}\n", control.output)
        for label, (listing, records) in census_cases().items():
            with self.subTest(census=label):
                data = with_census(LANDING.ci_authentication_fixture(), listing, records)
                self.assert_census_fixture(data, label, listing)
                run = authenticate_ci_step(data)
                self.assertIn(f"GET {PREFIX}/pulls/{PR}", run.calls)
                self.assertNotIn("unprovided API", run.result.stderr)
                self.assertEqual(run.output, "",
                                 f"CI authentication accepted evidence head {LANDING.EVIDENCE} beside: {label}")
                self.assertEqual(run.result.returncode, 1, run.result.stderr)
                self.assertEqual(polls(run), [])
                self.assertEqual(listing_reads(run, listing), [FIRST_PAGE_QUERY[listing]], run.calls)

    def test_publication_refuses_a_shared_or_unclassifiable_evidence_head(self) -> None:
        control = LANDING.revalidate_publication_head(with_census(LANDING.live_tuple()))
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertEqual(control.result.stdout, f"{LANDING.PUBLICATION_PROBE}\n")
        # The publisher reads through the check-store curl fake, which serves a
        # list fixture `per_page` records at a time, so an oversized page is
        # exercised through the CI step's gh fake only.
        for label, (listing, records) in census_cases().items():
            if label.endswith(OVERSIZED_PAGE):
                continue
            with self.subTest(census=label):
                data = with_census(LANDING.live_tuple(), listing, records)
                self.assert_census_fixture(data, label, listing)
                run = LANDING.revalidate_publication_head(data)
                self.assertIn(f"GET {PREFIX}/pulls/{PR}", run.calls)
                self.assertNotIn("unprovided API", run.result.stderr)
                self.assertEqual(run.result.stdout, "",
                                 f"publication revalidation accepted evidence head {LANDING.EVIDENCE} beside: {label}")
                self.assertEqual(run.result.returncode, 1, run.result.stderr)
                self.assertEqual(listing_reads(run, listing), [FIRST_PAGE_QUERY[listing]], run.calls)

    def test_full_publication_writes_nothing_beside_a_closed_unmerged_sibling(self) -> None:
        control = publish_without_stubs(LANDING.publication_fixture())
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertEqual(len(LANDING.checks_on(control.data, "Security contract", LANDING.APP_ID, "success")), 1)
        data = LANDING.publication_fixture()
        closed = listed_pull(LANDING.OTHER_PR, state="closed")
        data[f"{PREFIX}/commits/{LANDING.EVIDENCE}/pulls"].append(closed)
        data[f"{PREFIX}/pulls/{LANDING.OTHER_PR}"] = closed | {"merged": False}
        self.assertEqual([pull["number"] for pull in data[f"{PREFIX}/pulls"]], [PR])
        run = publish_without_stubs(data)
        self.assertIn(f"GET {PREFIX}/pulls/{PR}", run.calls)
        self.assertNotIn("unprovided API", run.result.stderr)
        self.assertEqual(LANDING.checks_on(run.data, "Security contract", LANDING.APP_ID, "success"), [],
                         f"Security contract was published on {LANDING.EVIDENCE} while closed pull request "
                         f"{LANDING.OTHER_PR} also had that head")
        self.assertEqual(LANDING.check_mutations(run), [])
        self.assertEqual(run.result.returncode, 1, run.result.stderr)


ATTESTATION_STEP = ("enterprise-evidence-finalizer.yml", "authorize-security-check-publication",
                    "Verify exact CI merge binding attestation")
BINDING_PROBE, CERTIFICATE_PROBE = "merge binding verified", "certificate verified"
REPOSITORY_ID, REPOSITORY_OWNER_ID = "1195888645", "1"
BINDING_ARTIFACT_ID = 812

# Writes an artifact archive the way `curl --output` stores a download: the
# step's umask applies, so the file is created 0600 under umask 077.
ARTIFACT_CURL = r'''#!/usr/bin/env -S python3 -I -S
import base64,json,os,sys,urllib.parse
args=sys.argv[1:]
url=next(a for a in args if a.startswith('https://api.github.com/'))
path=urllib.parse.urlsplit(url).path.lstrip('/')
with open(os.environ['API_LOG'],'a') as log: log.write('GET '+path+'\n')
if '--output' not in args or '--request' in args:
    sys.stderr.write('unsupported artifact request\n');sys.exit(2)
with open(os.environ['API_FIXTURE']) as fixture: record=json.load(fixture).get(path)
if not isinstance(record,dict) or '__binary_base64' not in record:
    sys.stderr.write('unprovided API '+path+'\n');sys.exit(22)
with open(args[args.index('--output')+1],'wb') as output: output.write(base64.b64decode(record['__binary_base64']))
'''


def attestation_context(capture_merge: str, ci_merge: str) -> dict[str, str]:
    """Step wiring values: the capture merge from validate-capture and the CI title merge from the CI step."""
    return {
        "needs.validate-capture.outputs.base_ref": "main", "needs.validate-capture.outputs.base_sha": REGEN_BASE,
        "needs.validate-capture.outputs.merge_commit_sha": capture_merge,
        "needs.validate-capture.outputs.merge_tree_sha": REGEN_TREE,
        "steps.ci.outputs.ci_merge_sha": ci_merge, "steps.ci.outputs.ci_run_attempt": "1",
        "steps.ci.outputs.ci_run_id": str(LANDING.CI_RUN), "steps.bind.outputs.ci_workflow_id": str(LANDING.CI_WORKFLOW),
        "steps.bind.outputs.evidence_sha": REGEN_HEAD, "steps.bind.outputs.head_ref": LANDING.HEAD_REF,
        "steps.bind.outputs.pr_number": str(PR), "steps.bind.outputs.security_definition_sha": DEFINITION,
        "github.token": LANDING.ACTIONS_TOKEN,
    }


def merge_binding(merge: str, parents: tuple[str, str] = (REGEN_BASE, REGEN_HEAD), tree: str = REGEN_TREE) -> dict:
    """The binding enterprise-hardening.yml signs in the CI run that tested `merge`."""
    return {
        "base": {"ref": "main", "repository": REPOSITORY, "repository_id": REPOSITORY_ID, "sha": REGEN_BASE},
        "builder": {"definition_sha": DEFINITION, "workflow_path": ".github/workflows/enterprise-hardening.yml"},
        "caller": {"definition_sha": merge, "workflow_path": ".github/workflows/ci.yml",
                   "workflow_ref": f"{REPOSITORY}/.github/workflows/ci.yml@refs/pull/{PR}/merge"},
        "ci": {"event": "pull_request", "run_attempt": "1", "run_id": str(LANDING.CI_RUN),
               "run_name": f"CI N={PR} E={REGEN_HEAD} B={REGEN_BASE} M={merge}", "workflow_id": str(LANDING.CI_WORKFLOW)},
        "head": {"ref": LANDING.HEAD_REF, "repository": REPOSITORY, "repository_id": REPOSITORY_ID, "sha": REGEN_HEAD},
        "merge": {"parents": list(parents), "ref": f"refs/pull/{PR}/merge", "sha": merge, "tree_sha": tree},
        "pull_request_number": str(PR),
        "repository": {"id": REPOSITORY_ID, "name": REPOSITORY, "owner": "bb-connor", "owner_id": REPOSITORY_OWNER_ID,
                       "visibility": "public"},
        "schema": "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1",
    }


def canonical(value: dict) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def binding_artifact(binding: dict) -> tuple[dict, bytes]:
    bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
              "verificationMaterial": {"certificate": {"rawBytes": "MIIB"}, "tlogEntries": []},
              "dsseEnvelope": {"payload": "e30=", "payloadType": "application/vnd.in-toto+json", "signatures": []}}
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as writer:
        for name, content in (("ci-merge-binding.json", canonical(binding) + "\n"),
                              ("ci-merge-binding.bundle.jsonl", canonical(bundle) + "\n")):
            info = zipfile.ZipInfo(name)
            info.external_attr, info.compress_type = 0o100444 << 16, zipfile.ZIP_DEFLATED
            writer.writestr(info, content.encode())
    content = archive.getvalue()
    created = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 600))
    updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 590))
    record = {"id": BINDING_ARTIFACT_ID, "node_id": "MDg6QXJ0aWZhY3Q4MTI=",
              "name": f"ci-merge-binding-{LANDING.CI_RUN}-1", "size_in_bytes": len(content),
              "url": f"https://api.github.com/{PREFIX}/actions/artifacts/{BINDING_ARTIFACT_ID}",
              "archive_download_url": f"https://api.github.com/{PREFIX}/actions/artifacts/{BINDING_ARTIFACT_ID}/zip",
              "expired": False, "digest": "sha256:" + hashlib.sha256(content).hexdigest(),
              "created_at": created, "updated_at": updated, "expires_at": "2026-12-31T00:00:00Z",
              "workflow_run": {"id": LANDING.CI_RUN, "repository_id": int(REPOSITORY_ID),
                               "head_repository_id": int(REPOSITORY_ID), "head_branch": LANDING.HEAD_REF,
                               "head_sha": REGEN_HEAD}}
    return record, content


def verify_binding(binding: dict, *, capture_merge: str = CAPTURE_MERGE, ci_merge: str = CAPTURE_MERGE):
    """Run the attestation step from its start through the binding checks, before the GitHub CLI download."""
    record, content = binding_artifact(binding)
    data = {f"{PREFIX}/actions/runs/{LANDING.CI_RUN}/artifacts": {"total_count": 1, "artifacts": [record]},
            f"{PREFIX}/actions/artifacts/{BINDING_ARTIFACT_ID}/zip": {
                "__binary_base64": base64.b64encode(content).decode()}}
    script, environment = render_step(*ATTESTATION_STEP, attestation_context(capture_merge, ci_merge))
    script = script[:script.index('gh_archive="${RUNNER_TEMP}/')] + f'echo "{BINDING_PROBE}"\n'
    with unittest.mock.patch.object(LANDING, "CHECK_STORE_CURL", ARTIFACT_CURL):
        return LANDING.run_offline_step(REFUSAL_TRACE + script, data, environment)


def certificate(digests: dict[str, str]) -> dict:
    """Fulcio certificate extensions as `gh attestation verify --format json` reports them."""
    signer = f"https://github.com/{REPOSITORY}/.github/workflows/enterprise-hardening.yml@{DEFINITION}"
    return {
        "certificateIssuer": "CN=sigstore-intermediate,O=sigstore.dev", "subjectAlternativeName": signer,
        "issuer": "https://token.actions.githubusercontent.com", "githubWorkflowTrigger": "pull_request",
        "githubWorkflowName": "CI", "githubWorkflowRepository": REPOSITORY,
        "githubWorkflowRef": f"refs/pull/{PR}/merge", "buildSignerURI": signer, "buildSignerDigest": DEFINITION,
        "runnerEnvironment": "github-hosted", "sourceRepositoryURI": f"https://github.com/{REPOSITORY}",
        "sourceRepositoryRef": f"refs/pull/{PR}/merge", "sourceRepositoryIdentifier": REPOSITORY_ID,
        "sourceRepositoryOwnerURI": "https://github.com/bb-connor", "sourceRepositoryOwnerIdentifier": REPOSITORY_OWNER_ID,
        "buildConfigURI": f"https://github.com/{REPOSITORY}/.github/workflows/ci.yml@refs/pull/{PR}/merge",
        "buildTrigger": "pull_request",
        "runInvocationURI": f"https://github.com/{REPOSITORY}/actions/runs/{LANDING.CI_RUN}/attempts/1",
        "sourceRepositoryVisibilityAtSigning": "public",
    } | digests


CERTIFICATE_DIGESTS = ("sourceRepositoryDigest", "buildConfigDigest", "githubWorkflowSHA")


def verify_certificate(binding: dict, digests: dict[str, str], *, capture_merge: str = CAPTURE_MERGE,
                       ci_merge: str = CAPTURE_MERGE):
    """Run the attestation step's statement and certificate checks on a verification result."""
    binding_text = canonical(binding)
    binding_sha256 = hashlib.sha256((binding_text + "\n").encode()).hexdigest()
    signed_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 595))
    verification = [{"verificationResult": {
        "statement": {"_type": "https://in-toto.io/Statement/v1",
                      "predicateType": "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1",
                      "subject": [{"name": "ci-merge-binding.json", "digest": {"sha256": binding_sha256}}],
                      "predicate": binding},
        "signature": {"certificate": certificate(digests)},
        "verifiedTimestamps": [{"type": "Tlog", "uri": "https://rekor.sigstore.dev", "timestamp": signed_at}],
    }}]
    script, environment = render_step(*ATTESTATION_STEP, attestation_context(capture_merge, ci_merge))
    script = script[script.index('statement="$('):script.index("while read -r timestamp; do")]
    return LANDING.run_offline_step(
        REFUSAL_TRACE + "set -euo pipefail\nshopt -s inherit_errexit\n" + script + f'echo "{CERTIFICATE_PROBE}"\n', {},
        environment | {"verification_json": "verification.json", "binding": binding_text,
                       "binding_sha256": binding_sha256, "repository_id": REPOSITORY_ID,
                       "repository_owner_id": REPOSITORY_OWNER_ID},
        files={"verification.json": json.dumps(verification).encode()})


def producer_line(field: str) -> str:
    """The unique attestation step line that checks `field`, as bash reports it on refusal."""
    script, _ = render_step(*ATTESTATION_STEP, attestation_context(CAPTURE_MERGE, CAPTURE_MERGE))
    lines = [line.strip() for line in script.splitlines() if f"'{field}'" in line and line.strip().startswith("test ")]
    if len(lines) != 1:
        raise AssertionError(f"expected one attestation check of {field}, found {lines}")
    return lines[0]


class AttestationRegenerationOriginalTests(unittest.TestCase):
    """Original (RED at e82ee26673, turns GREEN when P4 lands).

    `Verify exact CI merge binding attestation` binds the signed binding and its
    certificate to the CI title merge M_ci. A binding and certificate for a
    regenerated M_ci with the recorded parents and tree verify, and a
    certificate digest of the capture merge cannot stand in for M_ci.
    """

    def test_binding_and_certificate_for_a_regenerated_ci_merge_verify(self) -> None:
        control = verify_binding(merge_binding(CAPTURE_MERGE))
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertEqual(control.result.stdout, f"{BINDING_PROBE}\n")
        self.assertEqual(control.calls, [f"GET {PREFIX}/actions/runs/{LANDING.CI_RUN}/artifacts?per_page=100",
                                         f"GET {PREFIX}/actions/artifacts/{BINDING_ARTIFACT_ID}/zip"])
        signed_control = verify_certificate(merge_binding(CAPTURE_MERGE), dict.fromkeys(CERTIFICATE_DIGESTS, CAPTURE_MERGE))
        self.assertEqual(signed_control.result.returncode, 0, signed_control.result.stderr)
        self.assertEqual(signed_control.result.stdout, f"{CERTIFICATE_PROBE}\n")
        binding = merge_binding(REGENERATED_ONCE)
        self.assertEqual((binding["merge"]["parents"], binding["merge"]["tree_sha"]), ([REGEN_BASE, REGEN_HEAD], REGEN_TREE))
        run = verify_binding(binding, ci_merge=REGENERATED_ONCE)
        self.assertIn(f"GET {PREFIX}/actions/artifacts/{BINDING_ARTIFACT_ID}/zip", run.calls)
        self.assertNotIn("unprovided API", run.result.stderr)
        self.assertEqual(run.result.returncode, 0,
                         f"the signed binding for regenerated test merge {REGENERATED_ONCE} (parents [{REGEN_BASE}, {REGEN_HEAD}], "
                         f"tree {REGEN_TREE}) was refused against capture merge {CAPTURE_MERGE} (refused at: {refusal(run)})")
        self.assertEqual(run.result.stdout, f"{BINDING_PROBE}\n")
        signed = verify_certificate(binding, dict.fromkeys(CERTIFICATE_DIGESTS, REGENERATED_ONCE), ci_merge=REGENERATED_ONCE)
        self.assertEqual(signed.result.returncode, 0,
                         f"the certificate signed on regenerated test merge {REGENERATED_ONCE} was refused against capture "
                         f"merge {CAPTURE_MERGE} (refused at: {refusal(signed)})")
        self.assertEqual(signed.result.stdout, f"{CERTIFICATE_PROBE}\n")

    def test_certificate_digests_of_the_capture_merge_cannot_stand_in_for_the_ci_merge(self) -> None:
        binding = merge_binding(REGENERATED_ONCE)
        control = verify_certificate(merge_binding(CAPTURE_MERGE), dict.fromkeys(CERTIFICATE_DIGESTS, CAPTURE_MERGE))
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        cases = {"every digest": dict.fromkeys(CERTIFICATE_DIGESTS, CAPTURE_MERGE)} | {
            field: dict.fromkeys(CERTIFICATE_DIGESTS, REGENERATED_ONCE) | {field: CAPTURE_MERGE} for field in CERTIFICATE_DIGESTS}
        for label, digests in cases.items():
            with self.subTest(certificate=label):
                expected = producer_line("." + next(field for field in CERTIFICATE_DIGESTS if digests[field] == CAPTURE_MERGE))
                run = verify_certificate(binding, digests, ci_merge=REGENERATED_ONCE)
                self.assertEqual(run.result.stdout, "",
                                 f"a certificate with {label} = capture merge {CAPTURE_MERGE} verified a binding for CI "
                                 f"merge {REGENERATED_ONCE}")
                self.assertEqual(refusal(run), expected)
                self.assertEqual(run.result.returncode, 1)


if __name__ == "__main__":
    unittest.main()

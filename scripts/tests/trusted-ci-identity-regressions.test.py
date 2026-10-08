#!/usr/bin/env python3
"""Exercise the dedicated Security contract identity rules with offline APIs.

Every case runs the real finalizer publisher, revoker or landing auditor through
the offline API fakes of the landing regression suite. Workflow cases execute
the step body from its workflow definition with the environment its own `env:`
mapping resolves to; only the App key, JWT and installation-token exchange is
cut, and the offline installation token stands in for its output.

Each class carries exactly one label:
- Original: RED on the current producers at the claimed boundary, GREEN once
  the candidate identity rules land;
- Preservation: GREEN on the current producers and required to stay GREEN;
- Prospective: the post-change expectation for a boundary the current
  producers cannot reach, skipped with the exact reason.
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
import unittest
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

REPOSITORY, PR, SOURCE, EVIDENCE = LANDING.REPOSITORY, LANDING.PR, LANDING.SOURCE, LANDING.EVIDENCE
BASE, MERGE, TREE, DEFINITION = LANDING.BASE, LANDING.MERGE, LANDING.TREE, LANDING.DEFINITION
APP_ID, CI_RUN, CI_WORKFLOW, FINALIZER_RUN = LANDING.APP_ID, LANDING.CI_RUN, LANDING.CI_WORKFLOW, LANDING.FINALIZER_RUN
PREFIX = f"repos/{REPOSITORY}"
REPOSITORY_ID = "1195888645"
INSTALLATION_ID = "1"
DEDICATED_APP = {"id": APP_ID, "slug": "chio-security-authority"}
# The authorized source before the current one; S is part of the candidate
# identity, so its authority is another identity on the same evidence head.
PRIOR_SOURCE = "2" * 40

# The bash ERR trap reports the producer command that refused, so a refusal can
# be attributed to an exact check rather than to any failure.
REFUSAL_TRACE = "set -E\ntrap 'printf \"refused-at: %s\\n\" \"${BASH_COMMAND}\" >&2' ERR\n"
EXPRESSION = re.compile(r"\$\{\{ ([A-Za-z0-9_.-]+) \}\}")
PUBLISHER = ("enterprise-evidence-finalizer.yml", "publish-security-contract",
             "Reconcile exact five-context merge authority")
REVOKER = ("security-contract-revocation.yml", "revoke-security-contract",
           "Revoke exact Actions mirrors and dedicated App namespace")


def refusal(run) -> str:
    lines = [line[len("refused-at: "):] for line in run.result.stderr.splitlines() if line.startswith("refused-at: ")]
    return lines[0] if lines else ""


def render_step(definition: tuple[str, str, str], context: dict[str, str]) -> tuple[str, dict[str, str]]:
    """Return the step script and the environment its own `env:` mapping resolves to."""
    name, job, step = definition
    job_definition = LANDING.workflow(name)["jobs"][job]
    matches = [item for item in job_definition["steps"] if item.get("name") == step]
    if len(matches) != 1:
        raise AssertionError(f"{name} {job} has {len(matches)} steps named {step!r}")
    environment = {}
    for key, expression in (job_definition.get("env", {}) | matches[0].get("env", {})).items():
        match = EXPRESSION.fullmatch(expression)
        if match is None or match.group(1) not in context:
            raise AssertionError(f"{step}: no offline value for {key}: {expression}")
        environment[key] = context[match.group(1)]
    if EXPRESSION.search(matches[0]["run"]):
        raise AssertionError(f"{step}: inline workflow expression")
    return matches[0]["run"], environment


def without_token_exchange(script: str, resume: str) -> str:
    """Cut the App key, JWT and installation-token exchange, resuming at `resume`."""
    start = script.index('private_key="${RUNNER_TEMP}')
    return script[:start] + script[script.index(resume, start):]


def app_context() -> dict[str, str]:
    return {
        "github.ref": "refs/heads/main", "github.sha": DEFINITION, "github.token": LANDING.ACTIONS_TOKEN,
        "secrets.CHIO_SECURITY_APP_PRIVATE_KEY_PEM": "offline-key-never-read",
        "vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA": SOURCE,
        "vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA": DEFINITION,
        "vars.CHIO_SECURITY_APP_ID": str(APP_ID), "vars.CHIO_SECURITY_APP_INSTALLATION_ID": INSTALLATION_ID,
    }


def installation_repositories() -> dict:
    return {"installation/repositories": {"total_count": 1, "repository_selection": "selected",
                                          "repositories": [{"id": int(REPOSITORY_ID), "full_name": REPOSITORY}]}}


def run_publisher(data: dict, extra_outputs: dict[str, str] | None = None):
    """Run the publish-security-contract step for the sealed binding of PR, E, M and S."""
    binding = LANDING.publication_binding()
    outputs = {
        "authorized_source_sha": SOURCE, "ci_aggregate_check_run_id": "505", "ci_run_attempt": "1",
        "ci_run_id": str(CI_RUN), "ci_workflow_id": str(CI_WORKFLOW), "evidence_sha": EVIDENCE,
        "external_id": LANDING.EXTERNAL_ID, "merge_commit_sha": MERGE, "pr_number": str(PR),
        "publication_binding_digest": hashlib.sha256(binding.encode()).hexdigest(),
        "publication_binding_json": binding, "security_definition_sha": DEFINITION,
    } | (extra_outputs or {})
    context = app_context() | {
        f"needs.authorize-security-check-publication.outputs.{key}": value for key, value in outputs.items()
    } | {
        "github.repository_id": REPOSITORY_ID, "github.run_attempt": "1", "github.run_id": str(FINALIZER_RUN),
        "vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA": EVIDENCE,
    }
    script, environment = render_step(PUBLISHER, context)
    script = without_token_exchange(script, 'repositories="$({')
    return LANDING.run_offline_step(REFUSAL_TRACE + script, data | installation_repositories(),
                                    environment | {"installation_token": LANDING.INSTALLATION_TOKEN},
                                    collect=("summary.md",))


def run_revoker(data: dict, event_name: str, pr: int = PR):
    """Run the revoke-security-contract step for a bound denial of the pull request, E, M and S."""
    manual = event_name == "workflow_dispatch"
    outputs = {
        "authorized_source_sha": SOURCE, "base_sha": BASE, "create_missing": "true", "evidence_sha": EVIDENCE,
        "merge_commit_sha": MERGE, "merge_tree_sha": TREE, "pr_number": str(pr),
        "reason": "operator-security-revocation" if manual else "ci-regression",
        "security_definition_sha": DEFINITION,
    }
    context = app_context() | {f"needs.bind-revocation.outputs.{key}": value for key, value in outputs.items()} | {
        "github.event.repository.default_branch": "main", "github.event_name": event_name,
        "vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA": "0" * 40 if manual else EVIDENCE,
    }
    script, environment = render_step(REVOKER, context)
    script = without_token_exchange(script, 'repositories="$(curl')
    return LANDING.run_offline_step(REFUSAL_TRACE + script, data | installation_repositories(),
                                    environment | {"installation_token": LANDING.INSTALLATION_TOKEN},
                                    collect=("summary.md",))


def own_authority() -> dict:
    """The positive authority the finalizer published for this PR, E, M and S."""
    (check,) = LANDING.positive_authority_checks()
    return check


def other_identity_authority() -> dict:
    """A positive authority for the same PR, E and M published under PRIOR_SOURCE, older than any denial."""
    check = copy.deepcopy(own_authority())
    external_id = f"arc:{PR}:{EVIDENCE}:{MERGE}:{PRIOR_SOURCE}"
    metadata = json.loads(check["output"]["text"])
    metadata["identity"]["authorized_source_sha"] = PRIOR_SOURCE
    check.update(id=603, external_id=external_id, check_suite={"id": 604})
    check["output"] = {"title": "Chio security authority",
                       "summary": f"Dedicated chio-security-authority approval for {external_id}.",
                       "text": json.dumps(metadata)}
    return check


def namespace_store(check: dict) -> str:
    return f"{PREFIX}/commits/{check['head_sha']}/check-runs"


def namespace_listing(check: dict) -> str:
    return (f"GET {namespace_store(check)}?app_id={APP_ID}&check_name=Security%20contract"
            "&filter=all&per_page=100&page=1")


def with_namespace(data: dict, *checks: dict) -> dict:
    for check in checks:
        store = data.setdefault(namespace_store(check), {"total_count": 0, "check_runs": []})
        store["check_runs"].append(copy.deepcopy(check))
        store["total_count"] = len(store["check_runs"])
        data[f"{PREFIX}/check-runs/{check['id']}"] = copy.deepcopy(check)
    return data


def bad_ci_publication_fixture(*checks: dict) -> dict:
    """A publication whose CI history for E holds an authenticated failed run."""
    data = LANDING.publication_fixture()
    bad = LANDING.prior_failed_ci_run(MERGE)
    LANDING.add_ci_runs(data, LANDING.pull_request_ci_run(CI_RUN, MERGE), bad)
    return with_namespace(data, *checks)


def revocation_fixture(*checks: dict) -> dict:
    return with_namespace(LANDING.revoker_fixture(), *checks)


def stored(run, check: dict) -> dict:
    (match,) = [item for item in run.data[namespace_store(check)]["check_runs"] if item["id"] == check["id"]]
    return match


def denied_projection(check: dict) -> tuple:
    return ("Security contract", check["head_sha"], DEDICATED_APP, check["external_id"], "completed", "failure",
            check["output"]["text"])


def projection(check: dict) -> tuple:
    return (check["name"], check["head_sha"], check["app"], check["external_id"], check["status"],
            check["conclusion"], check["output"]["text"])


AUDIT_ENVIRONMENT = ("AUDIT_WORKFLOW_SHA", "GH_TOKEN", "PR_NUMBER", "SECURITY_APP_ID", "SECURITY_DEFINITION_SHA")


def run_auditor(data: dict, pr: int = PR, workflow_sha: str = LANDING.PROTECTED):
    """Run the admin-override-audit step with the real auditor script."""
    job = LANDING.workflow("admin-override-audit.yml")["jobs"]["audit"]
    if tuple(sorted(job["env"])) != AUDIT_ENVIRONMENT:
        raise AssertionError(f"audit job environment changed: {sorted(job['env'])}")
    body = next(step["run"] for step in job["steps"] if "run" in step)
    script = ROOT / "scripts/audit-security-merge-qualification.py"
    run = LANDING.run_offline_step(body, data, {
        "AUDIT_WORKFLOW_SHA": workflow_sha, "GH_TOKEN": "offline-fixture-token", "PR_NUMBER": str(pr),
        "SECURITY_APP_ID": str(APP_ID), "SECURITY_DEFINITION_SHA": DEFINITION, "PYTHONDONTWRITEBYTECODE": "1",
    }, files={f"authorized-auditor/scripts/{script.name}": script.read_bytes()}, collect=("audit.json",))
    return run, json.loads(run.collected.get("audit.json", "{}"))


def unverified(pr: int, error: str) -> dict:
    return {"status": "unverified", "repository": REPOSITORY, "pr_number": str(pr), "error": error,
            "bypass_attribution": "unestablished"}


def retarget(data: dict, mapping: dict[str, str]) -> dict:
    """Rename commit SHAs throughout a fixture, keys included."""
    text = json.dumps(data)
    for old, new in mapping.items():
        text = text.replace(old, new)
    return json.loads(text)


def set_ci_title(data: dict, run_id: int, title: str) -> None:
    for key in (f"{PREFIX}/actions/runs/{run_id}", f"{PREFIX}/actions/runs/{run_id}/attempts/1"):
        data[key]["display_title"] = title
    for listing in (f"{PREFIX}/actions/runs", f"{PREFIX}/actions/workflows/ci.yml/runs"):
        for run in data[listing]["workflow_runs"]:
            if run["id"] == run_id:
                run["display_title"] = title


class ForeignIdentityDenialOriginalTests(unittest.TestCase):
    """Original (genuine RED at b94eb3788e+D, GREEN once the canonical member is the oldest): C-P6-1.

    A denial normalizes the dedicated App namespace it lists. Its canonical
    member is the oldest member, whatever its external ID, so an existing
    success of another candidate identity in that namespace is failed in place
    with its external ID and text kept. The finalizer's
    `normalize_bad_ci_namespace` and the revoker's `normalize_namespace` select
    the canonical member by the denial's own external ID; with only another
    identity present both stop before any write and its success stands.
    """

    def assert_denied_in_place(self, run, existing: dict, reason: str) -> None:
        mutations = LANDING.check_mutations(run)
        self.assertEqual(
            mutations, [f"PATCH {PREFIX}/check-runs/{existing['id']}"],
            f"{reason}: mutations {mutations}; namespace listings "
            f"{run.calls.count(namespace_listing(existing))}; refused at: {refusal(run)}")
        self.assertEqual(projection(stored(run, existing)), denied_projection(existing))
        self.assertEqual(len(run.data[namespace_store(existing)]["check_runs"]), 1)

    def test_finalizer_bad_ci_denial_fails_the_success_of_another_identity(self) -> None:
        own = own_authority()
        control = run_publisher(bad_ci_publication_fixture(own))
        self.assertEqual(control.result.returncode, 1, control.result.stderr)
        self.assertEqual(control.collected["summary.md"],
                         f"Bad current CI completion permanently tombstoned {LANDING.EXTERNAL_ID}.\n")
        self.assertEqual(LANDING.check_mutations(control), [f"PATCH {PREFIX}/check-runs/{own['id']}"])
        self.assertEqual(projection(stored(control, own)), denied_projection(own))

        other = other_identity_authority()
        self.assertEqual(projection(other), ("Security contract", own["head_sha"], DEDICATED_APP,
                                             f"arc:{PR}:{EVIDENCE}:{MERGE}:{PRIOR_SOURCE}", "completed", "success",
                                             other["output"]["text"]))
        run = run_publisher(bad_ci_publication_fixture(other))
        self.assertEqual(run.result.returncode, 1, run.result.stderr)
        for call in (f"GET {PREFIX}/contents/.github/workflows/enterprise-evidence-finalizer.yml?ref={DEFINITION}",
                     "GET installation/repositories?per_page=100",
                     f"GET {PREFIX}/{LANDING.CI_HISTORY_QUERY}",
                     f"GET {PREFIX}/actions/runs/{LANDING.PRIOR_CI_RUN}/attempts/1",
                     f"GET {PREFIX}/pulls/{PR}", namespace_listing(other)):
            self.assertIn(call, run.calls)
        self.assert_denied_in_place(
            run, other, f"the finalizer denial for E left the success {other['external_id']} standing")

    def test_revoker_denial_fails_the_success_of_another_identity(self) -> None:
        own, other = own_authority(), other_identity_authority()
        for event_name in ("workflow_run", "workflow_dispatch"):
            with self.subTest(event=event_name):
                control = run_revoker(revocation_fixture(own), event_name)
                self.assertEqual(control.result.returncode, 0, control.result.stderr)
                self.assertEqual(LANDING.check_mutations(control), [f"PATCH {PREFIX}/check-runs/{own['id']}"])
                self.assertEqual(projection(stored(control, own)), denied_projection(own))

                run = run_revoker(revocation_fixture(other), event_name)
                for call in (f"GET {PREFIX}/contents/.github/workflows/security-contract-revocation.yml?ref={DEFINITION}",
                             "GET installation/repositories?per_page=100", namespace_listing(other)):
                    self.assertIn(call, run.calls)
                self.assert_denied_in_place(
                    run, other, f"the {event_name} revocation for E left the success {other['external_id']} standing")
                self.assertEqual(run.result.returncode, 0, run.result.stderr)


OTHER_PR, OTHER_MERGE = LANDING.OTHER_PR, LANDING.OTHER_MERGE
DENIAL_EXTERNAL_ID = f"chio:v3:deny:{EVIDENCE}"
STRAY_STATUS_ID = 55861913852


def evidence_head_denial() -> dict:
    """A dedicated App denial member carrying the evidence-head deny ID and revocation v2 text."""
    text = json.dumps({
        "authorized_source_sha": SOURCE, "evidence_sha": EVIDENCE,
        "observed": {"base_sha": BASE, "merge_commit_sha": MERGE, "merge_tree_sha": TREE, "pr_number": str(PR)},
        "reason": "operator-security-revocation", "schema": "chio.security-check-revocation.v2",
        "security_definition_sha": DEFINITION,
    }, sort_keys=True, separators=(",", ":"))
    return {
        "id": 607, "name": "Security contract", "head_sha": own_authority()["head_sha"],
        "external_id": DENIAL_EXTERNAL_ID, "status": "completed", "conclusion": "failure",
        "completed_at": "2026-10-06T00:07:00Z",
        "details_url": f"https://github.com/{REPOSITORY}/actions/runs/902/attempts/1",
        "output": {"title": "Chio security authority revoked",
                   "summary": f"Authority {DENIAL_EXTERNAL_ID} is permanently revoked for operator-security-revocation.",
                   "text": text},
        "app": DEDICATED_APP, "check_suite": {"id": 608},
    }


class DenialMemberPublicationPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D, must stay GREEN): C-P6-2.

    The publisher publishes only into an empty namespace or over its own exact
    success. A denial member in the namespace, the tombstone the revoker creates
    for this candidate or a member carrying the evidence-head deny ID, stops the
    step with no POST or PATCH and the member unchanged. The current publisher
    refuses both through its own-exact-success rule; it has no deny-ID rule of
    its own.
    """

    def assert_refused_unchanged(self, member: dict) -> None:
        data = with_namespace(LANDING.publication_fixture(), member)
        run = run_publisher(data)
        self.assertIn(f"GET {PREFIX}/{LANDING.CI_HISTORY_QUERY}", run.calls)
        self.assertIn(namespace_listing(member), run.calls)
        self.assertEqual(run.result.returncode, 1, run.result.stderr)
        self.assertEqual(LANDING.check_mutations(run), [], f"refused at: {refusal(run)}")
        self.assertEqual(run.data[namespace_store(member)], data[namespace_store(member)])
        self.assertEqual(run.collected, {})

    def test_publisher_creates_the_dedicated_authority_in_an_empty_namespace(self) -> None:
        run = run_publisher(LANDING.publication_fixture())
        self.assertEqual(run.result.returncode, 0, run.result.stderr)
        self.assertEqual(LANDING.check_mutations(run), [f"POST {PREFIX}/check-runs"])
        (created,) = run.data[namespace_store(own_authority())]["check_runs"]
        self.assertEqual((created["name"], created["head_sha"], created["app"], created["external_id"],
                          created["status"], created["conclusion"]),
                         ("Security contract", own_authority()["head_sha"], DEDICATED_APP, LANDING.EXTERNAL_ID,
                          "completed", "success"))

    def test_publisher_refuses_the_revoker_tombstone_for_its_candidate(self) -> None:
        for event_name in ("workflow_run", "workflow_dispatch"):
            with self.subTest(event=event_name):
                revocation = run_revoker(LANDING.revoker_fixture(), event_name)
                self.assertEqual(revocation.result.returncode, 0, revocation.result.stderr)
                self.assertEqual(LANDING.check_mutations(revocation), [f"POST {PREFIX}/check-runs"])
                (tombstone,) = revocation.data[namespace_store(own_authority())]["check_runs"]
                self.assertEqual((tombstone["name"], tombstone["app"], tombstone["external_id"], tombstone["status"],
                                  tombstone["conclusion"]),
                                 ("Security contract", DEDICATED_APP, LANDING.EXTERNAL_ID, "completed", "failure"))
                self.assert_refused_unchanged(tombstone)

    def test_publisher_refuses_an_evidence_head_deny_member(self) -> None:
        self.assert_refused_unchanged(evidence_head_denial())


class StrayMirrorOnEvidenceHeadPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D, must stay GREEN): C-D1 and C-D2 on E.

    Authority is the dedicated App `Security contract` alone. Actions-App
    `Security mirror / ...` check runs and commit statuses on the evidence head,
    successful, failed or duplicated, neither grant nor withdraw it, and the
    auditor never reads commit statuses.
    """

    @staticmethod
    def stray_status(state: str) -> dict:
        # Shape of the commit status an Actions token posted under a mirror
        # context on a pull request head (observed status 55861913852).
        return {"id": STRAY_STATUS_ID, "state": state, "context": "Security mirror / Build, lint, test",
                "description": None, "target_url": f"https://github.com/{REPOSITORY}/actions/runs/37730820466/attempts/1",
                "created_at": "2026-10-08T05:07:51Z", "updated_at": "2026-10-08T05:07:51Z",
                "creator": {"login": "github-actions[bot]", "id": 41898282, "type": "Bot"}}

    def test_stray_mirror_checks_and_statuses_on_the_evidence_head_leave_the_audit_verified(self) -> None:
        baseline, baseline_report = run_auditor(LANDING.snapshot())
        self.assertEqual(baseline.result.returncode, 0, baseline.result.stderr)
        self.assertEqual(baseline_report["status"], "verified")
        self.assertEqual(baseline_report["qualification"]["authority_check_run_ids"], [own_authority()["id"]])
        failed = LANDING.foreign_mirror(EVIDENCE) | {"conclusion": "failure"}
        duplicate = LANDING.foreign_mirror(EVIDENCE) | {"id": 113139755294}
        for label, checks, state in (("success", (LANDING.foreign_mirror(EVIDENCE),), "success"),
                                     ("failure", (failed,), "failure"),
                                     ("duplicate", (LANDING.foreign_mirror(EVIDENCE), duplicate), "success")):
            with self.subTest(mirror=label):
                data = LANDING.snapshot()
                store = data.setdefault(f"{PREFIX}/commits/{EVIDENCE}/check-runs", {"total_count": 0, "check_runs": []})
                store["check_runs"].extend(copy.deepcopy(list(checks)))
                store["total_count"] = len(store["check_runs"])
                status = self.stray_status(state)
                data[f"{PREFIX}/commits/{EVIDENCE}/statuses"] = [status]
                data[f"{PREFIX}/commits/{EVIDENCE}/status"] = {
                    "state": state, "sha": EVIDENCE, "total_count": 1, "statuses": [copy.deepcopy(status)]}
                run, report = run_auditor(data)
                self.assertEqual(run.result.returncode, 0, run.result.stderr)
                self.assertEqual(report, baseline_report)
                self.assertEqual([call for call in run.calls if "/status" in call], [])


def another_pull_request_ci_run(data: dict) -> None:
    """A successful CI run on E titled for another pull request, with its own job inventory and checks."""
    run = copy.deepcopy(data[f"{PREFIX}/actions/runs/{CI_RUN}"])
    run.update(id=202, display_title=f"CI N={OTHER_PR} E={EVIDENCE} B={BASE} M={OTHER_MERGE}", check_suite_id=402)
    listing = data[f"{PREFIX}/actions/runs"]
    listing["workflow_runs"].append(run)
    listing["total_count"] = len(listing["workflow_runs"])
    data[f"{PREFIX}/actions/runs/202"] = copy.deepcopy(run)
    data[f"{PREFIX}/actions/runs/202/attempts/1"] = copy.deepcopy(run)
    jobs = []
    for offset, (name, _) in enumerate(LANDING.ORDINARY, 1):
        check = {"id": 600 + offset, "name": name, "head_sha": EVIDENCE, "status": "completed", "conclusion": "success",
                 "app": {"id": 15368, "slug": "github-actions"}, "check_suite": {"id": 402, "head_sha": EVIDENCE}}
        data[f"{PREFIX}/check-runs/{check['id']}"] = check
        jobs.append({"id": 750 + offset, "name": name, "run_id": 202, "head_sha": EVIDENCE, "status": "completed",
                     "conclusion": "success", "check_run_url": f"https://api.github.com/{PREFIX}/check-runs/{check['id']}"})
    data[f"{PREFIX}/actions/runs/202/attempts/1/jobs"] = {"total_count": len(jobs), "jobs": jobs}


class ForeignPullRequestAuthorityAuditPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D, must stay GREEN): C-B1.

    Two pull requests share the evidence head. The dedicated authority bound
    to PR N_a never qualifies the landing of PR N_b. The current auditor reads
    authority only on the test merges named by N_b's own CI titles and
    requires the external ID's PR to be N_b.
    """

    @staticmethod
    def sibling_landing() -> dict:
        """PR N_b landed at L with head E; PR N_a's authority stays on its own test merge."""
        data = LANDING.snapshot()
        another_pull_request_ci_run(data)
        data[f"{PREFIX}/git/commits/{OTHER_MERGE}"] = {
            "sha": OTHER_MERGE, "parents": [{"sha": BASE}, {"sha": EVIDENCE}], "tree": {"sha": TREE}}
        data[f"{PREFIX}/commits/{OTHER_MERGE}/check-runs"] = {"total_count": 0, "check_runs": []}
        data[f"{PREFIX}/contents/.github/workflows/ci.yml?ref={OTHER_MERGE}"] = {"sha": "3" * 40}
        data[f"{PREFIX}/pulls/{OTHER_PR}"] = copy.deepcopy(data[f"{PREFIX}/pulls/{PR}"]) | {"number": OTHER_PR}
        return data

    def test_authority_bound_to_another_pull_request_does_not_qualify_the_sibling_landing(self) -> None:
        control, control_report = run_auditor(self.sibling_landing())
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertEqual(control_report["qualification"]["pr_number"], PR)
        self.assertEqual(control_report["qualification"]["authority_check_run_ids"], [own_authority()["id"]])

        run, report = run_auditor(self.sibling_landing(), pr=OTHER_PR)
        self.assertIn(f"GET {PREFIX}/pulls/{OTHER_PR}", run.calls)
        self.assertIn(f"GET {PREFIX}/commits/{OTHER_MERGE}/check-runs?check_name=Security%20contract&app_id={APP_ID}"
                      "&filter=all&per_page=100&page=1", run.calls)
        self.assertEqual([call for call in run.calls if f"commits/{MERGE}/check-runs" in call], [])
        self.assertEqual(run.result.returncode, 1)
        self.assertEqual(report, unverified(OTHER_PR, "no unique authenticated qualification for this protected landing"))

    def test_authority_naming_another_pull_request_on_the_sibling_test_merge_is_refused(self) -> None:
        data = self.sibling_landing()
        foreign = copy.deepcopy(own_authority())
        foreign.update(id=609, head_sha=OTHER_MERGE, external_id=f"arc:{PR}:{EVIDENCE}:{OTHER_MERGE}:{SOURCE}")
        metadata = json.loads(foreign["output"]["text"])
        metadata["identity"]["merge_commit_sha"] = OTHER_MERGE
        foreign["output"]["text"] = json.dumps(metadata)
        data[f"{PREFIX}/commits/{OTHER_MERGE}/check-runs"] = {"total_count": 1, "check_runs": [foreign]}
        run, report = run_auditor(data, pr=OTHER_PR)
        self.assertIn(f"GET {PREFIX}/commits/{OTHER_MERGE}/check-runs?check_name=Security%20contract&app_id={APP_ID}"
                      "&filter=all&per_page=100&page=1", run.calls)
        self.assertEqual(run.result.returncode, 1)
        self.assertEqual(report, unverified(OTHER_PR, "dedicated authority external ID mismatch"))


class DuplicateOrForgedAuthorityPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D, must stay GREEN): QA4 in the namespace the auditor reads.

    The dedicated namespace qualifies only as an authentic singleton: a
    duplicate App success, or an App success whose metadata names another
    identity, leaves the landing unverified.
    """

    def test_duplicate_or_forged_dedicated_authority_is_not_verified(self) -> None:
        own = own_authority()
        forged = copy.deepcopy(own)
        metadata = json.loads(forged["output"]["text"])
        metadata["identity"]["authorized_source_sha"] = PRIOR_SOURCE
        forged["output"]["text"] = json.dumps(metadata)
        for label, checks, error in (
                ("duplicate", (own, copy.deepcopy(own) | {"id": 606}), "duplicate dedicated authority namespace"),
                ("forged metadata", (forged,), "check metadata does not bind the exact PR/S/E/M/CI tuple")):
            with self.subTest(namespace=label):
                data = LANDING.snapshot()
                data[namespace_store(own)] = {"total_count": len(checks), "check_runs": copy.deepcopy(list(checks))}
                run, report = run_auditor(data)
                self.assertEqual(run.result.returncode, 1)
                self.assertEqual(report, unverified(PR, error))


MATCH_COUNT_REFUSAL = 'test "$(jq -r \'length\' <<< "${matches}")" = "1"'
SUITE_REFUSAL = 'test "$(jq -r \'.check_suite.id\' <<< "${check_run}")" = "${check_suite_id}"'


class SourceCiIdentityPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D, must stay GREEN): QA3 on the current boundaries.

    Recorded CI identities grant nothing by themselves. The auditor accepts a
    source CI only as an authenticated successful attempt of the exact tuple,
    and derives every original check from that attempt's own job inventory;
    the finalizer's CI step requires exactly one job per required name, each
    bound to a check run of the attempt's own suite.
    """

    def test_auditor_refuses_source_ci_identities_that_are_not_the_authenticated_attempt(self) -> None:
        def source_ci(data: dict, **changes: str) -> None:
            check = data[namespace_store(own_authority())]["check_runs"][0]
            metadata = json.loads(check["output"]["text"])
            metadata["source_ci"].update(changes)
            check["output"]["text"] = json.dumps(metadata)

        def other_run(data: dict) -> None:
            another_pull_request_ci_run(data)
            source_ci(data, run_id="202")

        def other_workflow(data: dict) -> None:
            source_ci(data, workflow_id=str(LANDING.FINALIZER_WORKFLOW))

        def missing_job(data: dict) -> None:
            inventory = data[f"{PREFIX}/actions/runs/{CI_RUN}/attempts/1/jobs"]
            inventory["jobs"] = [job for job in inventory["jobs"] if job["name"] != "MSRV build and test"]
            inventory["total_count"] = len(inventory["jobs"])

        def other_suite_check(data: dict) -> None:
            another_pull_request_ci_run(data)
            job = data[f"{PREFIX}/actions/runs/{CI_RUN}/attempts/1/jobs"]["jobs"][0]
            job["check_run_url"] = f"https://api.github.com/{PREFIX}/check-runs/601"

        for label, change, error in (
                ("successful run titled for another pull request", other_run, "source CI is absent from the exact tuple"),
                ("another workflow identity", other_workflow, "historical workflow, title or source mismatch"),
                ("job inventory without a required job", missing_job, "source CI job is missing or duplicated"),
                ("check run of another attempt's suite", other_suite_check, "original check is not the exact source CI")):
            with self.subTest(source=label):
                data = LANDING.snapshot()
                change(data)
                run, report = run_auditor(data)
                self.assertEqual(run.result.returncode, 1)
                self.assertEqual(report, unverified(PR, error))

    def test_finalizer_ci_step_refuses_an_inventory_that_is_not_the_attempt_s_own(self) -> None:
        context = {
            "github.token": LANDING.ACTIONS_TOKEN, "needs.validate-capture.outputs.base_ref": "main",
            "needs.validate-capture.outputs.base_sha": BASE, "needs.validate-capture.outputs.merge_commit_sha": MERGE,
            "needs.validate-capture.outputs.merge_tree_sha": TREE, "steps.bind.outputs.ci_workflow_id": str(CI_WORKFLOW),
            "steps.bind.outputs.evidence_sha": EVIDENCE, "steps.bind.outputs.head_ref": LANDING.HEAD_REF,
            "steps.bind.outputs.pr_number": str(PR),
        }
        script, environment = render_step(("enterprise-evidence-finalizer.yml", "authorize-security-check-publication",
                                           "Authenticate exact successful current CI run"), context)

        def authenticate(data: dict):
            return LANDING.run_offline_step(REFUSAL_TRACE + script, data, environment, poll_limit=True)

        control = authenticate(LANDING.ci_authentication_fixture())
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertEqual(control.output, "aggregate_check_run_id=505\nbuild_check_run_id=501\nci_run_attempt=1\n"
                                         f"ci_run_id={CI_RUN}\ndeny_check_run_id=504\nmsrv_check_run_id=502\n"
                                         "vet_check_run_id=503\n")

        def duplicate_job(data: dict) -> None:
            inventory = data[f"{PREFIX}/actions/runs/{CI_RUN}/attempts/1/jobs"]
            inventory["jobs"].append(copy.deepcopy(inventory["jobs"][0]) | {"id": 511, "check_run_url":
                                     f"https://api.github.com/{PREFIX}/check-runs/511"})
            data[f"{PREFIX}/check-runs/511"] = copy.deepcopy(data[f"{PREFIX}/check-runs/501"]) | {"id": 511}
            inventory["total_count"] = len(inventory["jobs"])

        def other_suite(data: dict) -> None:
            data[f"{PREFIX}/check-runs/501"]["check_suite"] = {"id": 402}

        for label, change, refused in (
                ("duplicate required job", duplicate_job, MATCH_COUNT_REFUSAL),
                ("check run of another suite", other_suite,
                 SUITE_REFUSAL)):
            with self.subTest(inventory=label):
                data = LANDING.ci_authentication_fixture()
                change(data)
                run = authenticate(data)
                self.assertIn(f"GET {PREFIX}/actions/runs/{CI_RUN}/attempts/1/jobs?filter=all&per_page=100", run.calls)
                self.assertEqual(run.result.returncode, 1)
                self.assertEqual(refusal(run), refused)
                self.assertEqual(run.output, "")


# Observed test-merge regeneration in the scratch repository (pull request #12,
# c9-m-regeneration): refs/pull/12/merge moved 431bd0fe -> 8e280a3f -> 125f0b53
# while main, the head, both parents and the tree stayed the same, and the
# protected merge landed as 53cb59e3 with the same parents and tree.
C9_BASE, C9_HEAD, C9_TREE = (
    "35987ff31972277a0a062e7a3f2bdaafa75ea938", "6aa9248cbb25c1aa87c35ab4291b3e04da906ab8",
    "50c10956584f514238d6b48a54b164e6f538e30d",
)
C9_CAPTURE_MERGE, C9_CI_MERGE, C9_PUBLICATION_MERGE = (
    "431bd0fea0ef5d9e2c47a36228bcc7937aaa39b8", "8e280a3f86e88ff5337520c1ee61eaf881c65ca2",
    "125f0b53ef97e5dc5e3247d484b5fe53191919ba",
)
C9_LANDING = "53cb59e39b46cca3889c4b866db266ba237b1949"
NO_QUALIFICATION = "no unique authenticated qualification for this protected landing"


def c9_landing(ci_merge: str = C9_CI_MERGE) -> dict:
    """The c9 tuple in the current authority schema.

    The finalizer recorded the capture test merge and published on it; the CI
    title names `ci_merge`; PR 1160 landed at C9_LANDING.
    """
    data = retarget(LANDING.snapshot(), {EVIDENCE: C9_HEAD, BASE: C9_BASE, TREE: C9_TREE,
                                         LANDING.PROTECTED: C9_LANDING, MERGE: C9_CAPTURE_MERGE})
    set_ci_title(data, CI_RUN, f"CI N={PR} E={C9_HEAD} B={C9_BASE} M={ci_merge}")
    for merge in (C9_CI_MERGE, C9_PUBLICATION_MERGE):
        data[f"{PREFIX}/git/commits/{merge}"] = {
            "sha": merge, "parents": [{"sha": C9_BASE}, {"sha": C9_HEAD}], "tree": {"sha": C9_TREE}}
        data[f"{PREFIX}/commits/{merge}/check-runs"] = {"total_count": 0, "check_runs": []}
        data[f"{PREFIX}/contents/.github/workflows/ci.yml?ref={merge}"] = {"sha": "3" * 40}
    return data


class RegeneratedTupleLegacyAuditPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D, must stay GREEN): the current auditor stays fail-closed on c9.

    A current-schema authority recorded on the capture test merge does not
    qualify a landing whose CI title names a regenerated test merge with the
    same parents and tree: the auditor reads authority only on the CI title's
    test merge.
    """

    def test_current_schema_authority_on_the_capture_merge_does_not_qualify_a_regenerated_ci_merge(self) -> None:
        control, control_report = run_auditor(c9_landing(ci_merge=C9_CAPTURE_MERGE), workflow_sha=C9_LANDING)
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertEqual((control_report["qualification"]["merge_commit_sha"], control_report["protected_merge_commit_sha"],
                          control_report["protected_parents"], control_report["protected_tree_sha"]),
                         (C9_CAPTURE_MERGE, C9_LANDING, [C9_BASE, C9_HEAD], C9_TREE))
        data = c9_landing()
        for merge in (C9_CAPTURE_MERGE, C9_CI_MERGE, C9_LANDING):
            self.assertEqual(([parent["sha"] for parent in data[f"{PREFIX}/git/commits/{merge}"]["parents"]],
                              data[f"{PREFIX}/git/commits/{merge}"]["tree"]["sha"]), ([C9_BASE, C9_HEAD], C9_TREE))
        run, report = run_auditor(data, workflow_sha=C9_LANDING)
        self.assertIn(f"GET {PREFIX}/commits/{C9_CI_MERGE}/check-runs?check_name=Security%20contract&app_id={APP_ID}"
                      "&filter=all&per_page=100&page=1", run.calls)
        self.assertEqual([call for call in run.calls if f"commits/{C9_CAPTURE_MERGE}/check-runs" in call], [])
        self.assertEqual(run.result.returncode, 1)
        self.assertEqual(report, unverified(PR, NO_QUALIFICATION))


# Post-change shapes, used only by the prospective cases below.
BINDING_ARTIFACT_ID = 812
LEGACY_REFUSAL = "legacy M-keyed authority is not a v3 qualification"


def candidate_identity(pr: int = PR, base: str = C9_BASE, evidence: str = C9_HEAD, tree: str = C9_TREE,
                       source: str = SOURCE) -> dict:
    return {"schema": "chio.security-candidate-identity.v1", "repository": REPOSITORY, "repository_id": REPOSITORY_ID,
            "pr_number": str(pr), "base_sha": base, "evidence_sha": evidence, "merge_tree_sha": tree,
            "authorized_source_sha": source, "security_definition_sha": DEFINITION}


def digest_of(identity: dict) -> str:
    return hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def ci_merge_binding(merge: str = C9_CI_MERGE, pr: int = PR) -> bytes:
    """The ci-merge-binding.json the CI attestation job writes for run CI_RUN attempt 1."""
    owner = REPOSITORY.split("/")[0]
    binding = {
        "base": {"ref": "main", "repository": REPOSITORY, "repository_id": REPOSITORY_ID, "sha": C9_BASE},
        "builder": {"definition_sha": DEFINITION, "workflow_path": ".github/workflows/enterprise-hardening.yml"},
        "caller": {"definition_sha": merge, "workflow_path": ".github/workflows/ci.yml",
                   "workflow_ref": f"{REPOSITORY}/.github/workflows/ci.yml@refs/pull/{pr}/merge"},
        "ci": {"event": "pull_request", "run_attempt": "1", "run_id": str(CI_RUN),
               "run_name": f"CI N={pr} E={C9_HEAD} B={C9_BASE} M={merge}", "workflow_id": str(CI_WORKFLOW)},
        "head": {"ref": LANDING.HEAD_REF, "repository": REPOSITORY, "repository_id": REPOSITORY_ID, "sha": C9_HEAD},
        "merge": {"parents": [C9_BASE, C9_HEAD], "ref": f"refs/pull/{pr}/merge", "sha": merge, "tree_sha": C9_TREE},
        "pull_request_number": str(pr),
        "repository": {"id": REPOSITORY_ID, "name": REPOSITORY, "owner": owner, "owner_id": "1", "visibility": "public"},
        "schema": "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1",
    }
    return json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()


def binding_archive(binding: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("ci-merge-binding.json", binding)
    return buffer.getvalue()


def v3_authority(identity: dict, archive: bytes, binding: bytes, *, digest: str | None = None) -> dict:
    identity_digest = digest_of(identity) if digest is None else digest
    external_id = f"chio:v3:{identity['pr_number']}:{identity['evidence_sha']}:{identity_digest}"
    text = {
        "schema": "chio.security-check-authority.v3", "identity": identity, "identity_digest": identity_digest,
        "merge_observations": {"capture": C9_CAPTURE_MERGE, "ci": C9_CI_MERGE},
        "source_ci": {"run_attempt": "1", "run_id": str(CI_RUN), "workflow_id": str(CI_WORKFLOW)},
        "required_check_run_ids": {"build": "501", "deny": "504", "msrv": "502", "vet": "503"},
        "aggregate_check_run_id": "505",
        "ci_merge_binding": {"artifact_digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
                             "artifact_id": str(BINDING_ARTIFACT_ID),
                             "binding_sha256": hashlib.sha256(binding).hexdigest()},
        "publication_binding_digest": "2" * 64,
    }
    return {
        "id": 605, "name": "Security contract", "head_sha": identity["evidence_sha"], "status": "completed",
        "conclusion": "success", "external_id": external_id, "app": DEDICATED_APP,
        "details_url": f"https://github.com/{REPOSITORY}/actions/runs/{FINALIZER_RUN}/attempts/1",
        "completed_at": "2026-10-06T00:06:00Z", "check_suite": {"id": 606},
        "output": {"title": "Chio security authority",
                   "summary": f"Dedicated chio-security-authority approval for {external_id}.",
                   "text": json.dumps(text, sort_keys=True, separators=(",", ":"))},
    }


def v3_c9_landing(identity: dict | None = None, binding: bytes | None = None, *, digest: str | None = None,
                  expired: bool = False) -> dict:
    """The c9 landing with a v3 authority on E: M_ci != M_cap != M_pub != L, one parent pair and one tree."""
    identity = candidate_identity() if identity is None else identity
    binding = ci_merge_binding() if binding is None else binding
    archive = binding_archive(binding)
    data = c9_landing()
    data[f"{PREFIX}/commits/{C9_CAPTURE_MERGE}/check-runs"] = {"total_count": 0, "check_runs": []}
    authority = v3_authority(identity, archive, binding, digest=digest)
    data[f"{PREFIX}/commits/{C9_HEAD}/check-runs"] = {"total_count": 1, "check_runs": [authority]}
    data[f"{PREFIX}/contents/.github/workflows/ci.yml?ref={C9_LANDING}"] = {"sha": "3" * 40}
    aggregate = {"id": 505, "name": "Security contract", "head_sha": C9_HEAD, "status": "completed",
                 "conclusion": "success", "app": {"id": 15368, "slug": "github-actions"},
                 "check_suite": {"id": 401, "head_sha": C9_HEAD}}
    data[f"{PREFIX}/check-runs/505"] = aggregate
    inventory = data[f"{PREFIX}/actions/runs/{CI_RUN}/attempts/1/jobs"]
    inventory["jobs"].append({"id": 705, "name": "Security contract", "run_id": CI_RUN, "head_sha": C9_HEAD,
                              "status": "completed", "conclusion": "success",
                              "check_run_url": f"https://api.github.com/{PREFIX}/check-runs/505"})
    inventory["total_count"] = len(inventory["jobs"])
    data[f"{PREFIX}/actions/artifacts/{BINDING_ARTIFACT_ID}"] = {
        "id": BINDING_ARTIFACT_ID, "name": f"ci-merge-binding-{CI_RUN}-1", "size_in_bytes": len(archive),
        "archive_download_url": f"https://api.github.com/{PREFIX}/actions/artifacts/{BINDING_ARTIFACT_ID}/zip",
        "expired": expired, "digest": "sha256:" + hashlib.sha256(archive).hexdigest(),
        "created_at": "2026-10-06T00:03:00Z", "expires_at": "2027-01-04T00:03:00Z", "updated_at": "2026-10-06T00:03:00Z",
        "workflow_run": {"id": CI_RUN, "repository_id": int(REPOSITORY_ID), "head_repository_id": int(REPOSITORY_ID),
                         "head_branch": LANDING.HEAD_REF, "head_sha": C9_HEAD},
    }
    data[f"{PREFIX}/actions/artifacts/{BINDING_ARTIFACT_ID}/zip"] = {
        "__binary_base64": base64.b64encode(archive).decode()}
    return data


def audit_v3(data: dict, pr: int = PR):
    return run_auditor(data, pr=pr, workflow_sha=C9_LANDING)


V3_AUDITOR = ("prospective: the current auditor reads authority only on the CI title's test merge "
              "(commits/<M>/check-runs), accepts only `arc:` external IDs and v2 text, and never reads an "
              "evidence-head namespace, a candidate identity or a CI binding artifact, so a v3 authority on E "
              "is never reached and any refusal today is placement and schema, not this rule")


class CandidateIdentityAuditProspectiveTests(unittest.TestCase):
    """Prospective (cannot run before the v3 auditor lands): c9 positive, v3 negatives, C-B1 and QA4 on E.

    Each case is the expectation for the v3 auditor. The exact refusal texts
    other than the legacy one are fixed when that auditor lands.
    """

    def assert_unverified(self, data: dict, pr: int = PR, error: str | None = None) -> None:
        run, report = audit_v3(data, pr=pr)
        self.assertEqual(run.result.returncode, 1)
        self.assertEqual((report["status"], report["bypass_attribution"], set(report)),
                         ("unverified", "unestablished", {"status", "repository", "pr_number", "error",
                                                          "bypass_attribution"}))
        if error is not None:
            self.assertEqual(report["error"], error)

    @unittest.skip(V3_AUDITOR)
    def test_c9_regenerated_test_merges_verify_one_candidate_identity(self) -> None:
        identity = candidate_identity()
        self.assertEqual(len({C9_CI_MERGE, C9_CAPTURE_MERGE, C9_PUBLICATION_MERGE, C9_LANDING}), 4)
        run, report = audit_v3(v3_c9_landing())
        self.assertEqual(run.result.returncode, 0, run.result.stderr)
        self.assertEqual(report["status"], "verified")
        qualification = report["qualification"]
        self.assertEqual((qualification["identity"], qualification["identity_digest"], qualification["merge_observations"],
                          qualification["required_check_run_ids"], qualification["aggregate_check_run_id"],
                          qualification["authority_check_run_id"]),
                         (identity, digest_of(identity), {"capture": C9_CAPTURE_MERGE, "ci": C9_CI_MERGE},
                          {"build": "501", "deny": "504", "msrv": "502", "vet": "503"}, "505", 605))
        self.assertEqual((report["protected_merge_commit_sha"], report["protected_parents"], report["protected_tree_sha"]),
                         (C9_LANDING, [C9_BASE, C9_HEAD], C9_TREE))
        self.assertNotIn("merge_commit_sha", qualification)

    @unittest.skip(V3_AUDITOR)
    def test_identity_digest_mismatch_is_not_verified(self) -> None:
        self.assert_unverified(v3_c9_landing(digest="9" * 64))

    @unittest.skip(V3_AUDITOR)
    def test_identity_that_does_not_match_the_landing_is_not_verified(self) -> None:
        for label, identity in (("base", candidate_identity(base=LANDING.OTHER_BASE)),
                                ("tree", candidate_identity(tree="1" * 40)),
                                ("pull request", candidate_identity(pr=OTHER_PR))):
            with self.subTest(identity=label):
                self.assert_unverified(v3_c9_landing(identity))

    @unittest.skip(V3_AUDITOR)
    def test_legacy_external_id_on_the_evidence_head_is_not_a_v3_qualification(self) -> None:
        data = v3_c9_landing()
        (legacy,) = copy.deepcopy(c9_landing()[f"{PREFIX}/commits/{C9_CAPTURE_MERGE}/check-runs"]["check_runs"])
        legacy["head_sha"] = C9_HEAD
        data[f"{PREFIX}/commits/{C9_HEAD}/check-runs"] = {"total_count": 1, "check_runs": [legacy]}
        self.assert_unverified(data, error=LEGACY_REFUSAL)

    @unittest.skip(V3_AUDITOR)
    def test_authority_only_on_a_test_merge_is_not_verified(self) -> None:
        data = v3_c9_landing()
        authority = data[f"{PREFIX}/commits/{C9_HEAD}/check-runs"]["check_runs"][0] | {"head_sha": C9_CI_MERGE}
        data[f"{PREFIX}/commits/{C9_HEAD}/check-runs"] = {"total_count": 0, "check_runs": []}
        data[f"{PREFIX}/commits/{C9_CI_MERGE}/check-runs"] = {"total_count": 1, "check_runs": [authority]}
        self.assert_unverified(data)

    @unittest.skip(V3_AUDITOR)
    def test_required_check_run_ids_that_differ_from_the_source_inventory_are_not_verified(self) -> None:
        data = v3_c9_landing()
        authority = data[f"{PREFIX}/commits/{C9_HEAD}/check-runs"]["check_runs"][0]
        text = json.loads(authority["output"]["text"])
        text["required_check_run_ids"]["build"] = "601"
        authority["output"]["text"] = json.dumps(text, sort_keys=True, separators=(",", ":"))
        data[f"{PREFIX}/check-runs/601"] = copy.deepcopy(data[f"{PREFIX}/check-runs/501"]) | {"id": 601}
        self.assert_unverified(data)

    @unittest.skip(V3_AUDITOR)
    def test_ci_binding_artifact_that_does_not_bind_the_ci_merge_is_not_verified(self) -> None:
        tampered = v3_c9_landing()
        tampered[f"{PREFIX}/actions/artifacts/{BINDING_ARTIFACT_ID}/zip"] = {
            "__binary_base64": base64.b64encode(binding_archive(ci_merge_binding() + b" ")).decode()}
        for label, data in (("archive digest", tampered),
                            ("merge.sha", v3_c9_landing(binding=ci_merge_binding(merge=C9_PUBLICATION_MERGE))),
                            ("expired artifact", v3_c9_landing(expired=True))):
            with self.subTest(binding=label):
                self.assert_unverified(data)

    @unittest.skip(V3_AUDITOR)
    def test_authority_bound_to_another_pull_request_on_the_shared_head_is_not_verified(self) -> None:
        data = v3_c9_landing()
        data[f"{PREFIX}/pulls/{OTHER_PR}"] = copy.deepcopy(data[f"{PREFIX}/pulls/{PR}"]) | {"number": OTHER_PR}
        self.assert_unverified(data, pr=OTHER_PR)

    @unittest.skip(V3_AUDITOR)
    def test_duplicate_or_forged_authority_on_the_evidence_head_is_not_verified(self) -> None:
        duplicate = v3_c9_landing()
        namespace = duplicate[f"{PREFIX}/commits/{C9_HEAD}/check-runs"]
        namespace["check_runs"].append(copy.deepcopy(namespace["check_runs"][0]) | {"id": 610})
        namespace["total_count"] = 2
        forged = v3_c9_landing()
        authority = forged[f"{PREFIX}/commits/{C9_HEAD}/check-runs"]["check_runs"][0]
        text = json.loads(authority["output"]["text"])
        text["source_ci"]["run_id"] = "202"
        authority["output"]["text"] = json.dumps(text, sort_keys=True, separators=(",", ":"))
        for label, data in (("duplicate", duplicate), ("forged source CI", forged)):
            with self.subTest(namespace=label):
                self.assert_unverified(data)


class SharedHeadDenialProspectiveTests(unittest.TestCase):
    """Prospective (cannot run before the denial namespace moves to E): C-P6-1 for a sibling pull request."""

    @unittest.skip("prospective: the current revoker lists only commits/<M>/check-runs of the bound pull request "
                   "(`list_checks`), so a sibling's authority on E is outside every namespace it reads and a missing "
                   "PATCH today would be placement, not the canonical-member rule")
    def test_revocation_for_e_fails_a_sibling_pull_request_authority_on_e(self) -> None:
        identity = candidate_identity(pr=PR, base=BASE, evidence=EVIDENCE, tree=TREE)
        sibling = v3_authority(identity, b"", b"") | {"id": 611}
        data = with_namespace(LANDING.revoker_fixture(), sibling)
        data[f"{PREFIX}/pulls/{OTHER_PR}"] = LANDING.live_pull_request(number=OTHER_PR, merge=OTHER_MERGE,
                                                                       head_ref="evidence-copy")
        run = run_revoker(data, "workflow_dispatch", pr=OTHER_PR)
        self.assertIn(namespace_listing(sibling), run.calls)
        self.assertEqual(LANDING.check_mutations(run), [f"PATCH {PREFIX}/check-runs/{sibling['id']}"])
        self.assertEqual(projection(stored(run, sibling)), denied_projection(sibling))
        self.assertEqual(run.result.returncode, 0, run.result.stderr)


class PublicationSourceCiRevalidationProspectiveTests(unittest.TestCase):
    """Prospective (cannot run before `revalidate_source_ci_checks` exists): QA3 at publication."""

    @unittest.skip("prospective: the current publish step never re-reads the source CI attempt, its job inventory "
                   "or its check runs; the IDs it holds were sealed by the authorize job of the same run, and no "
                   "observed record shows a sealed check run changing after authorization, so a RED today would rest "
                   "on an unobserved fixture")
    def test_publisher_refuses_when_a_sealed_check_run_is_no_longer_the_source_attempt_s_success(self) -> None:
        data = LANDING.publication_fixture()
        for check in (LANDING.ci_authentication_fixture()[f"{PREFIX}/check-runs/{identifier}"] for identifier in range(501, 506)):
            data[f"{PREFIX}/check-runs/{check['id']}"] = copy.deepcopy(check)
        data[f"{PREFIX}/actions/runs/{CI_RUN}/attempts/1/jobs"] = copy.deepcopy(
            LANDING.ci_authentication_fixture()[f"{PREFIX}/actions/runs/{CI_RUN}/attempts/1/jobs"])
        data[f"{PREFIX}/check-runs/501"]["conclusion"] = "failure"
        identity = candidate_identity(base=BASE, evidence=EVIDENCE, tree=TREE)
        run = run_publisher(data, {"identity_json": json.dumps(identity, sort_keys=True, separators=(",", ":")),
                                   "identity_digest": digest_of(identity)})
        self.assertIn(f"GET {PREFIX}/actions/runs/{CI_RUN}/attempts/1", run.calls)
        self.assertIn(f"GET {PREFIX}/check-runs/501", run.calls)
        self.assertEqual(LANDING.check_mutations(run), [])
        self.assertEqual(run.result.returncode, 1)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
"""Exercise the publisher's bad-CI history scan and denial-only revocation offline.

Every case runs the real finalizer and revocation shell from the workflow
definitions through the offline API fakes of the landing regression suite,
with each step's environment resolved from its own `env:` wiring. Only the
GitHub App credential exchange is skipped; the installation token is the
offline check-store token. Original cases describe behaviour the producers
got wrong before their repairs; preservation cases pin refusals and denials
that must hold before and after the repairs; prospective design controls pin
expectations no producer could reach before the P5/P6 boundary and are never
genuine Originals.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path
from typing import NamedTuple
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
LANDING_SPEC = importlib.util.spec_from_file_location(
    "trusted_ci_landing_regressions", ROOT / "scripts/tests/trusted-ci-landing-regressions.test.py"
)
if LANDING_SPEC is None or LANDING_SPEC.loader is None:
    raise RuntimeError("cannot load the landing regression harness")
LANDING = importlib.util.module_from_spec(LANDING_SPEC)
sys.modules[LANDING_SPEC.name] = LANDING
LANDING_SPEC.loader.exec_module(LANDING)

REPOSITORY, PR, SOURCE, EVIDENCE, BASE, MERGE, DEFINITION = (
    LANDING.REPOSITORY, LANDING.PR, LANDING.SOURCE, LANDING.EVIDENCE, LANDING.BASE, LANDING.MERGE, LANDING.DEFINITION,
)
APP_ID, CI_RUN, CI_WORKFLOW, FINALIZER_RUN = LANDING.APP_ID, LANDING.CI_RUN, LANDING.CI_WORKFLOW, LANDING.FINALIZER_RUN
REPOSITORY_ID = "1195888645"
PREFIX = f"repos/{REPOSITORY}"
APP = {"id": APP_ID, "slug": "chio-security-authority"}
CHECK_RUN_POST = f"POST {PREFIX}/check-runs"
CI_HISTORY_GET = f"GET {PREFIX}/{LANDING.CI_HISTORY_QUERY}"
# The repository-wide census Z of pull_request runs on E, read after the
# per-workflow listing; every run the per-workflow listing holds must be in Z.
CI_CENSUS_GET = (f"GET {PREFIX}/actions/runs?event=pull_request&head_sha={EVIDENCE}&exclude_pull_requests=true"
                 "&per_page=100&page=1")
FINALIZER = "enterprise-evidence-finalizer.yml"
PUBLISHER_SETUP = [f"GET {PREFIX}/contents/.github/workflows/{FINALIZER}?ref={DEFINITION}"] * 2

# The candidate identity I of the fixture tuple and its digest K.
IDENTITY = {"authorized_source_sha": SOURCE, "base_sha": BASE, "evidence_sha": EVIDENCE, "merge_tree_sha": LANDING.TREE,
            "pr_number": str(PR), "repository": REPOSITORY, "repository_id": REPOSITORY_ID,
            "schema": "chio.security-candidate-identity.v1", "security_definition_sha": DEFINITION}
IDENTITY_JSON = json.dumps(IDENTITY, sort_keys=True, separators=(",", ":"))
IDENTITY_DIGEST = hashlib.sha256(IDENTITY_JSON.encode("ascii")).hexdigest()

# The Security contract namespace the finalizer and the revoker bind for the
# fixture tuple: every App check is written on E, a denial created for E
# carries the deny ID, and a positive authority carries the v3 ID of I. Every
# Original asserts its denial here, beside a control that the producers deny
# in exactly this namespace.
Y_HEAD, Y_EXTERNAL_ID = EVIDENCE, f"chio:v3:deny:{EVIDENCE}"
AUTHORITY_EXTERNAL_ID = f"chio:v3:{PR}:{EVIDENCE}:{IDENTITY_DIGEST}"

# What the binders observe of N, B, M and the merge tree for the fixture tuple.
# The listener learns the tree only from a verified merge-binding artifact,
# which a failed attestation job never uploads; the manual binder reads it from
# the recorded M.
LISTENER_OBSERVED = {"base_sha": BASE, "merge_commit_sha": MERGE, "merge_tree_sha": "", "pr_number": str(PR)}
MANUAL_OBSERVED = LISTENER_OBSERVED | {"merge_tree_sha": LANDING.TREE}


def revocation_text(reason: str, observed: dict[str, str]) -> dict:
    """The tombstone text the revoker writes for E; each observation is empty when the binder did not observe it."""
    return {"authorized_source_sha": SOURCE, "evidence_sha": EVIDENCE, "observed": observed, "reason": reason,
            "schema": "chio.security-check-revocation.v2", "security_definition_sha": DEFINITION}


ORIGINAL_FAKE_GH, ORIGINAL_CHECK_STORE_CURL = LANDING.FAKE_GH, LANDING.CHECK_STORE_CURL

# Non-2xx GitHub answers and raw listing pages, keyed as the fixture fakes key
# requests. `curl --fail --show-error` exits 22 and names the status; `gh api`
# prints the error body and exits 1. Every other request reaches the landing
# suite's fixture fakes unchanged.
HTTP_GH = r'''#!/usr/bin/env -S python3 -I -S
import json,os,sys,urllib.parse
parts=urllib.parse.urlsplit(next((a for a in sys.argv[1:] if a.startswith('repos/')),''))
ref=urllib.parse.parse_qs(parts.query).get('ref')
data=json.load(open(os.environ['API_FIXTURE']))
error=data.get('__http_errors',{}).get(parts.path+('?ref='+ref[0] if ref else ''))
if error:
    print(json.dumps(error['body'],separators=(',',':')))
    sys.stderr.write('gh: '+error['body']['message']+' (HTTP '+str(error['status'])+')\n');sys.exit(1)
os.execv(sys.executable,[sys.executable,'-I','-S',os.path.join(os.path.dirname(os.environ['API_FIXTURE']),'gh-store')]+sys.argv[1:])
'''

HTTP_CURL = r'''#!/usr/bin/env -S python3 -I -S
import json,os,sys,urllib.parse
args=sys.argv[1:]
parts=urllib.parse.urlsplit(next(a for a in args if a.startswith('https://api.github.com/')))
query=urllib.parse.parse_qs(parts.query)
path=parts.path.lstrip('/')
data=json.load(open(os.environ['API_FIXTURE']))
error=data.get('__http_errors',{}).get(path+('?ref='+query['ref'][0] if 'ref' in query else ''))
pages=data.get('__pages',{}).get(path)
if '--request' not in args and (error or pages):
    with open(os.environ['API_LOG'],'a') as log: log.write('GET '+path+('?'+parts.query if parts.query else '')+'\n')
    if error:
        sys.stderr.write('curl: (22) The requested URL returned error: '+str(error['status'])+'\n');sys.exit(22)
    print(json.dumps(pages[int(query.get('page',['1'])[0])-1]));sys.exit(0)
os.execv(sys.executable,[sys.executable,'-I','-S',os.path.join(os.path.dirname(os.environ['API_FIXTURE']),'curl-store')]+args)
'''

# The bash ERR trap reports each producer command that refused, innermost
# first, so a refusal is attributed to an exact check rather than to any failure.
REFUSAL_TRACE = (
    "set -E\n"
    "__refusal_newline=$'\\n'\n"
    "trap 'printf \"refused-at: %s\\n\" \"${BASH_COMMAND//\"${__refusal_newline}\"/ }\" >&2' ERR\n"
)
EXPRESSION = re.compile(r"\$\{\{ ([A-Za-z0-9_.-]+)( \|\| '')? \}\}")


def refusals(run) -> list[str]:
    return [" ".join(line[len("refused-at: "):].split()) for line in run.result.stderr.splitlines()
            if line.startswith("refused-at: ")]


def render_step(name: str, job: str, step: str, context: dict[str, str]) -> tuple[str, dict[str, str]]:
    """Return the step script and the environment its own `env:` wiring resolves to."""
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
    if "${{" in matches[0]["run"]:
        raise AssertionError(f"{step}: unresolved workflow expression")
    return matches[0]["run"], environment


def without_credential_exchange(script: str, resume: str) -> str:
    """Drop the App JWT and installation-token exchange; every other line runs."""
    return script[:script.index('private_key="${RUNNER_TEMP}')] + script[script.index(resume):]


def run_step(script: str, data: dict, environment: dict[str, str]):
    with mock.patch.object(LANDING, "FAKE_GH", HTTP_GH), mock.patch.object(LANDING, "CHECK_STORE_CURL", HTTP_CURL):
        return LANDING.run_offline_step(REFUSAL_TRACE + script, data, environment, files={
            "gh-store": ORIGINAL_FAKE_GH.encode(), "curl-store": ORIGINAL_CHECK_STORE_CURL.encode()})


def outputs(run) -> dict[str, str]:
    return dict(line.split("=", 1) for line in run.output.splitlines())


def server_error(data: dict, path: str) -> None:
    data.setdefault("__http_errors", {})[f"{PREFIX}/{path}"] = {
        "status": 502, "body": {"message": "Server Error", "status": "502"}}


def mutations(run) -> list[str]:
    return [call for call in run.calls if call.startswith(("POST ", "PATCH "))]


def app_checks(data: dict) -> list[dict]:
    """Every dedicated App check in the store, oldest first."""
    return sorted((check for key, store in data.items() if key.startswith(f"{PREFIX}/commits/") and key.endswith("/check-runs")
                   for check in store["check_runs"] if check["app"]["id"] == APP_ID), key=lambda check: check["id"])


def check_identity(check: dict) -> tuple:
    return (check["name"], check["app"], check["head_sha"], check["external_id"], check["status"], check["conclusion"])


def publisher_context() -> dict[str, str]:
    binding = LANDING.publication_binding()
    authorization = {
        "authorized_source_sha": SOURCE, "ci_aggregate_check_run_id": "505", "ci_run_attempt": "1",
        "ci_run_id": str(CI_RUN), "ci_workflow_id": str(CI_WORKFLOW), "evidence_sha": EVIDENCE,
        "external_id": LANDING.EXTERNAL_ID, "identity_digest": IDENTITY_DIGEST, "identity_json": IDENTITY_JSON,
        "merge_commit_sha": MERGE, "pr_number": str(PR),
        "publication_binding_digest": hashlib.sha256(binding.encode()).hexdigest(),
        "publication_binding_json": binding, "security_definition_sha": DEFINITION,
    }
    return {f"needs.authorize-security-check-publication.outputs.{key}": value for key, value in authorization.items()} | {
        "vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA": EVIDENCE, "github.run_attempt": "1",
        "github.run_id": str(FINALIZER_RUN), "github.token": LANDING.ACTIONS_TOKEN, "github.ref": "refs/heads/main",
        "github.sha": DEFINITION, "github.repository_id": REPOSITORY_ID, "vars.CHIO_SECURITY_APP_ID": str(APP_ID),
        "vars.CHIO_SECURITY_APP_INSTALLATION_ID": "1", "secrets.CHIO_SECURITY_APP_PRIVATE_KEY_PEM": "",
        "vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA": SOURCE, "vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA": DEFINITION,
    }


def run_publisher(data: dict):
    """Run `Reconcile exact five-context merge authority` for the fixture tuple."""
    script, environment = render_step(FINALIZER, "publish-security-contract",
                                      "Reconcile exact five-context merge authority", publisher_context())
    script = without_credential_exchange(script, "revalidate_live_publication_head() {")
    return run_step(script, data, environment | {"installation_token": LANDING.INSTALLATION_TOKEN})


def ci_run(run_id: int, conclusion: str | None = "success", attempt: int = 1) -> dict:
    """A CI run on E: the source run keeps the suite of its recorded check runs, every other run has its own."""
    suite = {} if run_id == CI_RUN else {"check_suite_id": 2 * run_id}
    return LANDING.pull_request_ci_run(run_id, MERGE, conclusion=conclusion, attempt=attempt, **suite)


def publisher_fixture(*runs: dict) -> dict:
    """An open pull request on E whose CI history holds the source run and `runs`."""
    data = LANDING.publication_fixture()
    LANDING.add_ci_runs(data, ci_run(CI_RUN), *runs)
    return data


def run_reads(run_id: int, attempts: int = 1) -> list[str]:
    """The scan's reads of one listed run: current, each attempt, then current again."""
    return ([f"GET {PREFIX}/actions/runs/{run_id}"]
            + [f"GET {PREFIX}/actions/runs/{run_id}/attempts/{attempt}" for attempt in range(1, attempts + 1)]
            + [f"GET {PREFIX}/actions/runs/{run_id}"])


def assert_bad_ci_denial(test: unittest.TestCase, run, bad_runs: list[tuple[int, int, str]]) -> None:
    """Exactly one Security contract failure for E, naming exactly `bad_runs`, and no publication."""
    test.assertEqual(mutations(run), [CHECK_RUN_POST], run.result.stderr)
    checks = app_checks(run.data)
    test.assertEqual([check_identity(check) for check in checks],
                     [("Security contract", APP, Y_HEAD, Y_EXTERNAL_ID, "completed", "failure")])
    text = json.loads(checks[0]["output"]["text"])
    test.assertEqual((text["reason"], text["bad_ci_runs"]), ("ci-regression", [
        {"conclusion": conclusion, "run_attempt": attempt, "run_id": run_id, "workflow_id": CI_WORKFLOW}
        for run_id, attempt, conclusion in bad_runs]))
    test.assertEqual(run.result.returncode, 1)


class PublisherReadErrorAfterObservedBadOriginalTests(unittest.TestCase):
    """Original (RED at b94eb3788e+D): an API error after an observed bad attempt (O-G1).

    `reconcile_bad_ci` reads the listed runs in ascending ID order. Run A=200
    has an authenticated failed attempt 1, which the scan reads first; the
    later `actions/runs/B` read of run B=202 answers HTTP 502. That read runs
    under `set -e` outside any condition, so the step exits before the
    bad-dominates-incomplete branch and writes nothing. The failure was
    observed and authenticated, so it must still deny E.
    Ported to the P6 interfaces in "test(security): port the revocation
    regressions to the evidence head".
    """

    def test_failed_attempt_read_before_a_later_run_read_error_still_denies_the_evidence_head(self) -> None:
        bad, unreadable = ci_run(200, conclusion="failure"), ci_run(202)
        LANDING.assert_authoritative_history(self, bad)
        control = run_publisher(publisher_fixture(bad, unreadable))
        self.assertEqual(control.calls[:13], PUBLISHER_SETUP + [CI_HISTORY_GET, CI_CENSUS_GET, *run_reads(200),
                                                                  *run_reads(CI_RUN), *run_reads(202)])
        assert_bad_ci_denial(self, control, [(200, 1, "failure")])

        data = publisher_fixture(bad, unreadable)
        server_error(data, "actions/runs/202")
        self.assertEqual((data[f"{PREFIX}/actions/runs/200/attempts/1"]["status"],
                          data[f"{PREFIX}/actions/runs/200/attempts/1"]["conclusion"]), ("completed", "failure"))
        run = run_publisher(data)
        self.assertNotIn("unprovided API", run.result.stderr)
        self.assertEqual(run.calls[:11], PUBLISHER_SETUP + [CI_HISTORY_GET, CI_CENSUS_GET, *run_reads(200),
                                                             *run_reads(CI_RUN), f"GET {PREFIX}/actions/runs/202"])
        self.assertEqual(mutations(run), [CHECK_RUN_POST],
                         f"the scan read failed attempt 1 of CI run 200, then the read of run 202 answered HTTP 502 and "
                         f"the step exited {run.result.returncode} with no denial; refused at: {refusals(run)}")
        assert_bad_ci_denial(self, run, [(200, 1, "failure")])


class PublisherReadErrorBeforeBadRunOriginalTests(unittest.TestCase):
    """Original (RED at b94eb3788e+D): an API error must not preempt the scan (O-G1, reversed order).

    Run B=200 is listed first and its `actions/runs/B` read answers HTTP 502;
    run A=202 holds the authenticated failed attempt. Today the step exits at
    B's read, so A is never read: this case does not show an observed bad
    being dropped. It pins that one unreadable run cannot hide an
    authenticated failure later in the same history, which must deny E.
    Ported to the P6 interfaces in "test(security): port the revocation
    regressions to the evidence head".
    """

    def test_run_read_error_before_the_failed_run_still_denies_the_evidence_head(self) -> None:
        unreadable, bad = ci_run(200), ci_run(202, conclusion="failure")
        LANDING.assert_authoritative_history(self, bad)
        control = run_publisher(publisher_fixture(unreadable, bad))
        self.assertEqual(control.calls[:13], PUBLISHER_SETUP + [CI_HISTORY_GET, CI_CENSUS_GET, *run_reads(200),
                                                                  *run_reads(CI_RUN), *run_reads(202)])
        assert_bad_ci_denial(self, control, [(202, 1, "failure")])

        data = publisher_fixture(unreadable, bad)
        server_error(data, "actions/runs/200")
        self.assertEqual((data[f"{PREFIX}/actions/runs/202/attempts/1"]["status"],
                          data[f"{PREFIX}/actions/runs/202/attempts/1"]["conclusion"]), ("completed", "failure"))
        run = run_publisher(data)
        self.assertNotIn("unprovided API", run.result.stderr)
        self.assertEqual(run.calls[:5], PUBLISHER_SETUP + [CI_HISTORY_GET, CI_CENSUS_GET,
                                                            f"GET {PREFIX}/actions/runs/200"])
        self.assertEqual(mutations(run), [CHECK_RUN_POST],
                         f"the read of CI run 200 answered HTTP 502 and the step exited {run.result.returncode} before "
                         f"reading failed run 202 (reads: {run.calls[2:]}); refused at: {refusals(run)}")
        assert_bad_ci_denial(self, run, [(202, 1, "failure")])



def with_attempts(data: dict, run_id: int, attempts: int, failed_attempt: int = 0) -> dict:
    """Give run `run_id` completed attempts 1..`attempts`, each successful except `failed_attempt`."""
    for attempt in range(1, attempts + 1):
        record = ci_run(run_id, conclusion="failure" if attempt == failed_attempt else "success", attempt=attempt)
        data[f"{PREFIX}/actions/runs/{run_id}/attempts/{attempt}"] = record
    return data


def first_scan(run) -> list[str]:
    """The reads of the first history scan: from the first listing up to the next one."""
    start = run.calls.index(CI_HISTORY_GET)
    end = run.calls.index(CI_HISTORY_GET, start + 1) if CI_HISTORY_GET in run.calls[start + 1:] else len(run.calls)
    return run.calls[start:end]


CEILING_RUN = 202


class PublisherAttemptCeilingOriginalTests(unittest.TestCase):
    """Original (RED at b94eb3788e+D): a CI run past the 100-attempt ceiling (O-G3).

    The attempt loop of `reconcile_bad_ci` (FIN:2876) has no bound, unlike the
    auditor (AUD:216-217) and the finalizer retry scan (FIN:3038). A run whose
    current attempt is 101 is read through attempt 101 and, with every attempt
    successful, the step publishes. A history the producer cannot bound is
    unavailable: refuse without a tombstone and read no attempt past 100.
    Fails today at the mutation assertion: the step POSTs a success publication.
    Ported to the P6 interfaces in "test(security): port the revocation
    regressions to the evidence head".
    """

    def test_run_past_the_attempt_ceiling_refuses_without_a_tombstone(self) -> None:
        bounded = run_publisher(with_attempts(publisher_fixture(ci_run(CEILING_RUN, attempt=100)), CEILING_RUN, 100))
        self.assertEqual(bounded.result.returncode, 0, bounded.result.stderr)
        self.assertEqual(first_scan(bounded)[:7], [CI_HISTORY_GET, CI_CENSUS_GET, *run_reads(CI_RUN),
                                                   f"GET {PREFIX}/actions/runs/{CEILING_RUN}",
                                                   f"GET {PREFIX}/actions/runs/{CEILING_RUN}/attempts/1"])
        self.assertEqual(mutations(bounded), [CHECK_RUN_POST])
        self.assertEqual([check_identity(check) for check in app_checks(bounded.data)],
                         [("Security contract", APP, Y_HEAD, AUTHORITY_EXTERNAL_ID, "completed", "success")])

        data = with_attempts(publisher_fixture(ci_run(CEILING_RUN, attempt=101)), CEILING_RUN, 101)
        self.assertEqual(data[f"{PREFIX}/actions/runs/{CEILING_RUN}"]["run_attempt"], 101)
        run = run_publisher(data)
        self.assertNotIn("unprovided API", run.result.stderr)
        self.assertEqual(run.calls[:8], PUBLISHER_SETUP + [CI_HISTORY_GET, CI_CENSUS_GET, *run_reads(CI_RUN),
                                                                f"GET {PREFIX}/actions/runs/{CEILING_RUN}"])
        past_ceiling = f"GET {PREFIX}/actions/runs/{CEILING_RUN}/attempts/101"
        scanned = [call for call in first_scan(run) if call.startswith(f"GET {PREFIX}/actions/runs/{CEILING_RUN}/attempts/")]
        self.assertEqual(mutations(run), [],
                         f"CI run {CEILING_RUN} at attempt 101 was scanned through attempt 101 ({len(scanned)} attempt "
                         f"reads in the first scan, {run.calls.count(past_ceiling)} reads of attempt 101 in all) and the "
                         f"step published {[check_identity(check) for check in app_checks(run.data)]}")
        self.assertEqual(run.calls.count(past_ceiling), 0)
        self.assertEqual(app_checks(run.data), [])
        self.assertNotEqual(run.result.returncode, 0)


RETIRED_CI_WORKFLOW, RETIRED_RUN = 98, 199


def retired_registration_run(conclusion: str = "failure") -> dict:
    """A `ci.yml` run on E recorded under the workflow ID of a replaced registration."""
    run = ci_run(RETIRED_RUN, conclusion=conclusion)
    run["workflow_id"] = RETIRED_CI_WORKFLOW
    return run


def registry_replacement_fixture() -> dict:
    """The current registration lists only the source run; the repository listing also holds the retired run."""
    data = publisher_fixture()
    retired = retired_registration_run()
    data[f"{PREFIX}/actions/runs/{RETIRED_RUN}"] = retired
    data[f"{PREFIX}/actions/runs/{RETIRED_RUN}/attempts/1"] = dict(retired)
    data[f"{PREFIX}/actions/runs"] = {"total_count": 2, "workflow_runs": [ci_run(CI_RUN), dict(retired)]}
    data[f"{PREFIX}/actions/workflows/ci.yml"] = {"id": CI_WORKFLOW, "path": ".github/workflows/ci.yml", "state": "active"}
    return data


class PublisherDualCensusOriginalTests(unittest.TestCase):
    """Original (RED at b94eb3788e+D): a failed run of a replaced `ci.yml` registration (O-G2).

    History discovery reads only `actions/workflows/ci.yml/runs` (FIN:2722),
    which lists the runs of the current registration. After the registration
    is replaced, a failed `ci.yml` run on E keeps the old workflow ID and is
    listed only by the repository-wide `actions/runs?event=pull_request&head_sha=E`.
    The step publishes. That failure must deny E. The case asserts the denial
    outcome only, not the class the repair gives such a run.
    Fails today at the conclusion assertion: the one App check is a success.
    Ported to the P6 interfaces in "test(security): port the revocation
    regressions to the evidence head", with its scan-path precondition on the
    repaired census path; RED provenance: Original 7c334778a2.
    """

    def test_failed_run_of_a_replaced_registration_denies_the_evidence_head(self) -> None:
        listed = ci_run(RETIRED_RUN, conclusion="failure")
        control = run_publisher(publisher_fixture(listed))
        self.assertEqual(control.calls[:10], PUBLISHER_SETUP + [CI_HISTORY_GET, CI_CENSUS_GET, *run_reads(RETIRED_RUN),
                                                                 *run_reads(CI_RUN)])
        assert_bad_ci_denial(self, control, [(RETIRED_RUN, 1, "failure")])

        data = registry_replacement_fixture()
        retired = data[f"{PREFIX}/actions/runs/{RETIRED_RUN}"]
        self.assertEqual((retired["path"], retired["event"], retired["head_sha"], retired["repository"]["id"],
                          retired["head_repository"]["id"], retired["status"], retired["conclusion"], retired["workflow_id"]),
                         (".github/workflows/ci.yml", "pull_request", EVIDENCE, 1195888645, 1195888645, "completed",
                          "failure", RETIRED_CI_WORKFLOW))
        self.assertEqual([run["id"] for run in data[f"{PREFIX}/actions/workflows/ci.yml/runs"]["workflow_runs"]], [CI_RUN])
        self.assertEqual([run["id"] for run in data[f"{PREFIX}/actions/runs"]["workflow_runs"]], [CI_RUN, RETIRED_RUN])
        run = run_publisher(data)
        self.assertNotIn("unprovided API", run.result.stderr)
        self.assertEqual(run.calls[:7], PUBLISHER_SETUP + [CI_HISTORY_GET, CI_CENSUS_GET, *run_reads(RETIRED_RUN)])
        listings = [call for call in run.calls if "/runs?" in call]
        self.assertEqual([check["conclusion"] for check in app_checks(run.data)], ["failure"],
                         f"the publisher read only {sorted(set(listings))} ({len(listings)} listing reads), never the "
                         f"repository-wide history holding failed run {RETIRED_RUN}, and its mutations were "
                         f"{mutations(run)} with {[check_identity(check) for check in app_checks(run.data)]}")
        self.assertEqual(mutations(run), [CHECK_RUN_POST])
        self.assertEqual([check_identity(check) for check in app_checks(run.data)],
                         [("Security contract", APP, Y_HEAD, Y_EXTERNAL_ID, "completed", "failure")])
        self.assertEqual(run.result.returncode, 1)


# The revoker: `bind-revocation`, then `revoke-security-contract` with its outputs.

REVOCATION = "security-contract-revocation.yml"
BINDER_OUTPUTS = tuple(LANDING.workflow(REVOCATION)["jobs"]["bind-revocation"]["outputs"])
FREEZE = "0" * 40
EVENT_RUN = LANDING.LATER_CI_RUN
CLOSED_AT = "2026-10-06T00:20:00Z"
LANDED = LANDING.PROTECTED
NOT_FOUND_DOCUMENTATION = {
    "git/commits": "https://docs.github.com/rest/git/commits#get-a-commit-object",
    "git/ref": "https://docs.github.com/rest/git/refs#get-a-reference",
    "contents": "https://docs.github.com/rest/repos/contents#get-repository-content",
}


class Revocation(NamedTuple):
    steps: tuple
    outputs: dict

    @property
    def data(self) -> dict:
        return self.steps[-1].data

    @property
    def calls(self) -> list[str]:
        return [call for step in self.steps for call in step.calls]


def not_found(data: dict, path: str) -> None:
    """Make `path` answer 404 as GitHub does, and drop any fixture record for it."""
    data.pop(f"{PREFIX}/{path}", None)
    kind = next(prefix for prefix in NOT_FOUND_DOCUMENTATION if path.startswith(prefix))
    data.setdefault("__http_errors", {})[f"{PREFIX}/{path}"] = {
        "status": 404, "body": {"message": "Not Found", "documentation_url": NOT_FOUND_DOCUMENTATION[kind], "status": "404"}}


def revoke_with(steps: tuple, event_name: str, committed_evidence: str) -> Revocation:
    """Run `revoke-security-contract` when the binder succeeded with `eligible=true`, as its job condition does."""
    bound = outputs(steps[-1])
    if steps[-1].result.returncode != 0 or bound.get("eligible") != "true":
        return Revocation(steps, bound)
    context = {f"needs.bind-revocation.outputs.{key}": bound.get(key, "") for key in BINDER_OUTPUTS} | {
        "github.event.repository.default_branch": "main", "github.event_name": event_name,
        "github.token": LANDING.ACTIONS_TOKEN, "vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA": SOURCE,
        "vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA": committed_evidence,
        "vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA": DEFINITION, "github.ref": "refs/heads/main",
        "github.sha": DEFINITION, "vars.CHIO_SECURITY_APP_ID": str(APP_ID), "vars.CHIO_SECURITY_APP_INSTALLATION_ID": "1",
        "secrets.CHIO_SECURITY_APP_PRIVATE_KEY_PEM": "",
    }
    script, environment = render_step(REVOCATION, "revoke-security-contract",
                                      "Revoke exact Actions mirrors and dedicated App namespace", context)
    revoke = run_step(without_credential_exchange(script, "list_checks() {"), steps[-1].data,
                      environment | {"installation_token": LANDING.INSTALLATION_TOKEN})
    return Revocation((*steps, revoke), bound)


def revoke_failed_ci(data: dict, event_run: dict, committed_evidence: str = EVIDENCE) -> Revocation:
    """The `workflow_run` path: resolve the completed run, bind it, then revoke."""
    context = {
        "github.event.workflow_run.conclusion": event_run["conclusion"] or "",
        "github.event.workflow_run.run_attempt": str(event_run["run_attempt"]),
        "github.event.workflow_run.id": str(event_run["id"]),
        "github.event.workflow_run.workflow_id": str(event_run["workflow_id"]),
        "github.event.action": "completed", "github.event.repository.default_branch": "main",
        "github.token": LANDING.ACTIONS_TOKEN, "github.ref": "refs/heads/main", "github.run_attempt": "1",
        "github.run_id": "901", "github.sha": DEFINITION, "github.repository_id": REPOSITORY_ID,
        "github.repository_owner_id": "1", "vars.CHIO_AUTHORIZED_SECURITY_SOURCE_SHA": SOURCE,
        "vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA": committed_evidence, "vars.CHIO_SECURITY_APP_ID": str(APP_ID),
        "vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA": DEFINITION,
    }
    script, environment = render_step(REVOCATION, "bind-revocation", "Resolve exact completed workflow identity", context)
    route = run_step(script, data, environment)
    if route.result.returncode != 0 or outputs(route).get("workflow_path") != ".github/workflows/ci.yml":
        return Revocation((route,), {})
    script, environment = render_step(REVOCATION, "bind-revocation", "Bind later failed CI rerun to existing authority",
                                      context)
    return revoke_with((route, run_step(script, route.data, environment)), "workflow_run", committed_evidence)


def revoke_manually(data: dict) -> Revocation:
    """The `workflow_dispatch` path under the all-zero freeze."""
    context = {
        "inputs.authorized_source_sha": SOURCE, "github.event.repository.default_branch": "main",
        "inputs.evidence_sha": EVIDENCE, "github.token": LANDING.ACTIONS_TOKEN, "inputs.merge_commit_sha": MERGE,
        "inputs.pr_number": str(PR), "inputs.reason": "operator-security-revocation", "github.actor": "bb-connor",
        "github.ref": "refs/heads/main", "github.run_id": "902", "github.sha": DEFINITION,
        "github.triggering_actor": "bb-connor", "github.run_attempt": "1",
        "vars.CHIO_ENTERPRISE_SECURITY_DEFINITION_SHA": DEFINITION,
    }
    script, environment = render_step(REVOCATION, "bind-revocation", "Bind frozen manual revocation", context)
    return revoke_with((run_step(script, data, environment),), "workflow_dispatch", FREEZE)


def add_revocation_records(data: dict, checks: tuple[dict, ...]) -> dict:
    """Add the commit E, the manual revoker's own run, and `checks` in the check store."""
    data[f"{PREFIX}/git/commits/{EVIDENCE}"] = {"sha": EVIDENCE, "parents": [{"sha": SOURCE}], "tree": {"sha": "e0" * 20}}
    data.setdefault(f"{PREFIX}/commits/{EVIDENCE}/check-runs", {"total_count": 0, "check_runs": []})
    data[f"{PREFIX}/actions/runs/902/attempts/1"] = LANDING.revoker_run(902, "workflow_dispatch")
    for check in checks:
        store = data.setdefault(f"{PREFIX}/commits/{check['head_sha']}/check-runs", {"total_count": 0, "check_runs": []})
        store["check_runs"].append(check)
        store["total_count"] = len(store["check_runs"])
        data[f"{PREFIX}/check-runs/{check['id']}"] = check
    return data


def revocation_fixture(live_merge: str = MERGE, checks: tuple[dict, ...] = ()) -> dict:
    """An open pull request on E at `live_merge` with the revoker's records."""
    return add_revocation_records(LANDING.revoker_fixture(live_merge=live_merge), checks)


def failed_event(display_title: str | None = None) -> dict:
    return LANDING.pull_request_ci_run(EVENT_RUN, MERGE, conclusion="failure", check_suite_id=404,
                                       display_title=display_title)


def listener_fixture(event_run: dict, live_merge: str = MERGE, checks: tuple[dict, ...] = ()) -> dict:
    """The revocation fixture plus the completed failed CI run, its jobs, and the listener's own run."""
    data = LANDING.failed_ci_listener_fixture(event_run, LANDING.failed_builder_jobs(event_run["id"]), live_merge=live_merge)
    return add_revocation_records(data, checks)


def close_pull_request(data: dict, merged: bool) -> None:
    """Close pull request N with head E, as the pulls API reports it; its test-merge ref is gone."""
    for key in (f"{PREFIX}/pulls/{PR}", f"{PREFIX}/pulls", f"{PREFIX}/commits/{EVIDENCE}/pulls"):
        records = data[key] if isinstance(data[key], list) else [data[key]]
        for record in records:
            if record["number"] == PR:
                record.update(state="closed", merged=merged, merged_at=CLOSED_AT if merged else None, closed_at=CLOSED_AT,
                              mergeable=None, mergeable_state="unknown")
                if merged:
                    record["merge_commit_sha"] = LANDED
    if merged:
        data[f"{PREFIX}/git/commits/{LANDED}"] = {"sha": LANDED, "parents": [{"sha": BASE}, {"sha": EVIDENCE}],
                                                  "tree": {"sha": LANDING.TREE}}
    not_found(data, f"git/ref/pull/{PR}/merge")


def move_pull_request_head(data: dict, head: str, merge: str) -> None:
    """Pull request N stays open after its head moved from E to `head`, with test merge `merge`."""
    for key in (f"{PREFIX}/pulls/{PR}", f"{PREFIX}/pulls"):
        for record in data[key] if isinstance(data[key], list) else [data[key]]:
            record["head"]["sha"], record["merge_commit_sha"] = head, merge
    data[f"{PREFIX}/git/ref/pull/{PR}/merge"]["object"]["sha"] = merge
    data[f"{PREFIX}/git/commits/{merge}"] = {"sha": merge, "parents": [{"sha": BASE}, {"sha": head}],
                                             "tree": {"sha": "1" * 40}}


def assert_revocation_denial(test: unittest.TestCase, revocation: Revocation, reason: str,
                             observed: dict[str, str]) -> None:
    """Exactly one POSTed Security contract failure for E in the revoker's namespace, with its exact text."""
    test.assertEqual(mutations(revocation), [CHECK_RUN_POST], revocation.steps[-1].result.stderr)
    checks = app_checks(revocation.data)
    test.assertEqual([check_identity(check) for check in checks],
                     [("Security contract", APP, Y_HEAD, Y_EXTERNAL_ID, "completed", "failure")])
    test.assertEqual(json.loads(checks[0]["output"]["text"]), revocation_text(reason, observed))
    test.assertEqual(revocation.steps[-1].result.returncode, 0, revocation.steps[-1].result.stderr)


def binder_refusal(revocation: Revocation) -> str:
    binder = revocation.steps[-1]
    return f"binder exit {binder.result.returncode}, outputs {revocation.outputs}, refused at {refusals(binder)[-1:]}"


LISTENER_SETUP = [
    f"GET {PREFIX}/actions/runs/{EVENT_RUN}/attempts/1",
    f"GET {PREFIX}/contents/.github/workflows/{REVOCATION}?ref={DEFINITION}",
    f"GET {PREFIX}/contents/.github/workflows/{REVOCATION}?ref={DEFINITION}",
    f"GET {PREFIX}/actions/runs/901/attempts/1",
    f"GET {PREFIX}/actions/runs/{EVENT_RUN}/attempts/1",
]
MANUAL_SETUP = [
    f"GET {PREFIX}/contents/.github/workflows/{REVOCATION}?ref={DEFINITION}",
    f"GET {PREFIX}/contents/.github/workflows/{REVOCATION}?ref={DEFINITION}",
    f"GET {PREFIX}/actions/runs/902/attempts/1",
    f"GET {PREFIX}/git/commits/{EVIDENCE}",
]


class ListenerClosedPullRequestOriginalTests(unittest.TestCase):
    """Original (RED at b94eb3788e+D): C-P5-1, a closed unmerged pull request on the committed E.

    The listener's create rule (REV:542-558) creates a tombstone only for an
    open pull request whose live test merge is the titled M; otherwise it binds
    existing members only and, finding none, outputs `eligible=false`
    (REV:570). An authenticated failed CI run for the committed E must deny E
    whatever the pull request's state, unless it merged with head E.
    Fails today at the binder-output assertion: `eligible=false`.
    Ported to the P6 interfaces in "test(security): port the revocation
    regressions to the evidence head".
    """

    def test_failed_ci_on_the_committed_head_of_a_closed_pull_request_denies_the_head(self) -> None:
        event = failed_event()
        LANDING.assert_authoritative_history(self, event)
        control = revoke_failed_ci(listener_fixture(event), event)
        self.assertEqual((control.outputs["eligible"], control.outputs["create_missing"]), ("true", "true"))
        assert_revocation_denial(self, control, "ci-regression", LISTENER_OBSERVED)

        data = listener_fixture(event)
        close_pull_request(data, merged=False)
        self.assertEqual((data[f"{PREFIX}/pulls/{PR}"]["state"], data[f"{PREFIX}/pulls/{PR}"]["merged"],
                          data[f"{PREFIX}/pulls/{PR}"]["head"]["sha"]), ("closed", False, EVIDENCE))
        run = revoke_failed_ci(data, event)
        self.assertNotIn("unprovided API", run.steps[-1].result.stderr)
        self.assertEqual(run.calls[:len(LISTENER_SETUP)], LISTENER_SETUP)
        self.assertIn(f"GET {PREFIX}/pulls/{PR}", run.steps[1].calls)
        self.assertEqual((run.outputs.get("eligible"), run.outputs.get("create_missing")), ("true", "true"),
                         f"failed CI run {EVENT_RUN} on committed head {EVIDENCE} of closed pull request {PR} was not "
                         f"bound for denial: {binder_refusal(run)}; mutations {mutations(run)}")
        assert_revocation_denial(self, run, "ci-regression", LISTENER_OBSERVED)


MOVED_HEAD, MOVED_MERGE = "c4" * 20, "c5" * 20


class ManualRevocationOffHeadOriginalTests(unittest.TestCase):
    """Original (RED at b94eb3788e+D): C-P5-8, manual revocation under the freeze.

    The manual binder requires pull request N to be open (REV:136) with head E
    (REV:138) and its live test merge to be the requested M. An owner-authored
    revocation under the all-zero freeze must deny E for a closed pull request
    and for one whose head moved off E.
    Fails today at the binder-output assertion: the binder exits 1 at REV:136
    or REV:138 with no outputs.
    Ported to the P6 interfaces in "test(security): port the revocation
    regressions to the evidence head".
    """

    def test_manual_revocation_denies_e_for_a_closed_or_moved_pull_request(self) -> None:
        control = revoke_manually(revocation_fixture())
        self.assertEqual((control.outputs["eligible"], control.outputs["create_missing"]), ("true", "true"))
        assert_revocation_denial(self, control, "operator-security-revocation", MANUAL_OBSERVED)

        for label in ("closed", "head moved off E"):
            with self.subTest(pull_request=label):
                data = revocation_fixture()
                if label == "closed":
                    close_pull_request(data, merged=False)
                else:
                    move_pull_request_head(data, MOVED_HEAD, MOVED_MERGE)
                self.assertEqual(data[f"{PREFIX}/git/commits/{MERGE}"]["parents"], [{"sha": BASE}, {"sha": EVIDENCE}])
                run = revoke_manually(data)
                self.assertNotIn("unprovided API", run.steps[-1].result.stderr)
                self.assertEqual(run.calls[:len(MANUAL_SETUP)], MANUAL_SETUP)
                self.assertEqual((run.outputs.get("eligible"), run.outputs.get("create_missing")), ("true", "true"),
                                 f"manual revocation of {EVIDENCE} under the freeze was refused for a {label} pull "
                                 f"request: {binder_refusal(run)}")
                assert_revocation_denial(self, run, "operator-security-revocation", MANUAL_OBSERVED)


def unavailable_test_merges(data: dict) -> None:
    """The CI-titled M and the capture M are absent: GitHub answers 404 for each commit and its `ci.yml`."""
    for merge in (MERGE, LANDING.PRIOR_MERGE):
        not_found(data, f"git/commits/{merge}")
        not_found(data, f"contents/.github/workflows/ci.yml?ref={merge}")


class ListenerUnavailableTestMergeOriginalTests(unittest.TestCase):
    """Original (RED at b94eb3788e+D): C-P5-3a and C-P5-3b at the binder boundary.

    The titled test merge M_ci and the capture merge M_cap are no longer
    readable, and the live test merge was regenerated. The listener reads M's
    `ci.yml` blob (REV:322) and M's commit (REV:334-339) before it binds any
    denial, so it exits without outputs. An authenticated failed CI run for
    the committed E must make E eligible for denial without M.
    Fails today at the binder-output assertion: the binder exits 1 at the
    REV:322 read. The denial itself is prospective (see
    `ListenerUnavailableTestMergeProspectiveTests`): with M absent there is no
    test-merge namespace to deny in.
    Ported to the P6 interfaces in "test(security): port the revocation
    regressions to the evidence head".
    """

    def test_failed_ci_on_the_committed_head_binds_without_the_historical_test_merge(self) -> None:
        event = failed_event()
        control = revoke_failed_ci(listener_fixture(event), event)
        self.assertEqual((control.outputs["eligible"], control.outputs["create_missing"], control.outputs["evidence_sha"]),
                         ("true", "true", EVIDENCE))

        data = listener_fixture(event, live_merge=LANDING.REGENERATED_MERGE)
        unavailable_test_merges(data)
        run = revoke_failed_ci(data, event)
        self.assertNotIn("unprovided API", run.steps[-1].result.stderr)
        self.assertEqual(run.calls[:len(LISTENER_SETUP) + 2], LISTENER_SETUP + [
            f"GET {PREFIX}/contents/.github/workflows/ci.yml?ref={SOURCE}",
            f"GET {PREFIX}/contents/.github/workflows/ci.yml?ref={EVIDENCE}"])
        self.assertEqual(
            (run.outputs.get("eligible"), run.outputs.get("create_missing"), run.outputs.get("evidence_sha")),
            ("true", "true", EVIDENCE),
            f"failed CI run {EVENT_RUN} on committed head {EVIDENCE} was not bound once its test merges "
            f"{MERGE} and {LANDING.PRIOR_MERGE} were unreadable: {binder_refusal(run)}")


MISMATCHED_HEAD = "c3" * 20


class ListenerMismatchedTitleOriginalTests(unittest.TestCase):
    """Original (RED at b94eb3788e+D): C-P5-9 at the binder boundary.

    The run title is `CI N=<N> E=<other> B=<B> M=<M>` while the API head is E.
    The listener requires the title's E to equal the API head (REV:306) and
    exits. A title is never authentication: the API identity alone binds E.
    Fails today at the binder-output assertion: the binder exits 1 at REV:306.
    The denial itself is prospective (see `ListenerMismatchedTitleProspectiveTests`):
    a mismatched title supplies no authenticated test merge to deny in.
    Ported to the P6 interfaces in "test(security): port the revocation
    regressions to the evidence head".
    """

    def test_failed_ci_with_a_mismatched_title_binds_the_api_head(self) -> None:
        valid = failed_event()
        control = revoke_failed_ci(listener_fixture(valid), valid)
        self.assertEqual((control.outputs["eligible"], control.outputs["create_missing"], control.outputs["evidence_sha"]),
                         ("true", "true", EVIDENCE))

        event = failed_event(f"CI N={PR} E={MISMATCHED_HEAD} B={BASE} M={MERGE}")
        LANDING.assert_authoritative_history(self, event)
        run = revoke_failed_ci(listener_fixture(event), event)
        self.assertNotIn("unprovided API", run.steps[-1].result.stderr)
        self.assertEqual(run.calls[:len(LISTENER_SETUP)], LISTENER_SETUP)
        self.assertEqual(
            (run.outputs.get("eligible"), run.outputs.get("create_missing"), run.outputs.get("evidence_sha")),
            ("true", "true", EVIDENCE),
            f"failed CI run {EVENT_RUN} with API head {EVIDENCE} and title E={MISMATCHED_HEAD} was not bound: "
            f"{binder_refusal(run)}")



class PublisherReadErrorPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D): an unreadable run with no failure anywhere (O-G1 control).

    With no authenticated failure in the history, a run whose
    `actions/runs/B` read answers HTTP 502 leaves the history unavailable: the
    step refuses with no check written, in either scan order.
    """

    def test_unreadable_run_without_a_failure_refuses_without_a_tombstone(self) -> None:
        for unreadable in (200, 202):
            with self.subTest(unreadable_run=unreadable):
                data = publisher_fixture(ci_run(200), ci_run(202))
                server_error(data, f"actions/runs/{unreadable}")
                run = run_publisher(data)
                self.assertNotIn("unprovided API", run.result.stderr)
                self.assertEqual(run.calls[:3], PUBLISHER_SETUP + [CI_HISTORY_GET])
                self.assertIn(f"GET {PREFIX}/actions/runs/{unreadable}", run.calls)
                self.assertEqual(mutations(run), [])
                self.assertEqual(app_checks(run.data), [])
                self.assertNotEqual(run.result.returncode, 0)


class PublisherAttemptCeilingPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D): a failure beside a run past the attempt ceiling (O-G3 control).

    A failed attempt still denies E when a run of the history is at attempt
    101: in another run, and at attempt 100 of that run. The second case stays
    GREEN only if the ceiling repair reads attempts 1..100 before it classifies
    the run unavailable; a repair that skips the whole run turns it RED.
    """

    def test_failure_in_another_run_still_denies_beside_a_run_past_the_ceiling(self) -> None:
        data = with_attempts(publisher_fixture(ci_run(200, conclusion="failure"), ci_run(CEILING_RUN, attempt=101)),
                             CEILING_RUN, 101)
        run = run_publisher(data)
        self.assertNotIn("unprovided API", run.result.stderr)
        self.assertEqual(run.calls[:7], PUBLISHER_SETUP + [CI_HISTORY_GET, CI_CENSUS_GET, *run_reads(200)])
        assert_bad_ci_denial(self, run, [(200, 1, "failure")])

    def test_failed_attempt_at_the_ceiling_still_denies_the_evidence_head(self) -> None:
        data = with_attempts(publisher_fixture(ci_run(CEILING_RUN, attempt=101)), CEILING_RUN, 101, failed_attempt=100)
        self.assertEqual(data[f"{PREFIX}/actions/runs/{CEILING_RUN}/attempts/100"]["conclusion"], "failure")
        run = run_publisher(data)
        self.assertNotIn("unprovided API", run.result.stderr)
        self.assertIn(f"GET {PREFIX}/actions/runs/{CEILING_RUN}/attempts/100", run.calls)
        assert_bad_ci_denial(self, run, [(CEILING_RUN, 100, "failure")])


def census_pages(*pages: tuple[int, list[int]]) -> list[dict]:
    return [{"total_count": total, "workflow_runs": [ci_run(run_id) for run_id in run_ids]} for total, run_ids in pages]


MALFORMED_CENSUS = {
    "total_count changes between pages": census_pages((101, [CI_RUN, *range(1001, 1100)]), (102, [1100])),
    "duplicate run ID": census_pages((2, [CI_RUN, CI_RUN])),
    "short page before the total": census_pages((3, [CI_RUN, 200])),
}


class PublisherCensusPagePreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D): malformed CI history listings (O-G2, C-A3).

    `list_matching_ci_runs` (FIN:2705-2789) refuses a listing whose total
    changes between pages, that repeats a run ID, or whose page is short before
    the total is collected. The history is then unavailable: the step refuses
    with no check written.
    """

    def test_malformed_history_listing_refuses_without_a_tombstone(self) -> None:
        for label, pages in MALFORMED_CENSUS.items():
            with self.subTest(listing=label):
                data = publisher_fixture()
                data["__pages"] = {f"{PREFIX}/actions/workflows/ci.yml/runs": pages}
                run = run_publisher(data)
                self.assertNotIn("unprovided API", run.result.stderr)
                self.assertEqual(run.calls[:3], PUBLISHER_SETUP + [CI_HISTORY_GET])
                self.assertEqual(mutations(run), [])
                self.assertEqual(app_checks(run.data), [])
                self.assertNotEqual(run.result.returncode, 0)


class PublisherDualCensusProspectiveTests(unittest.TestCase):
    """A current-registration run missing from the repository-wide history (O-G2 control).

    Prospective design control, activated at the P5/P6 boundary; never a genuine Original.
    """

    def test_per_workflow_run_missing_from_the_repository_history_refuses_without_a_tombstone(self) -> None:
        data = publisher_fixture(ci_run(203))
        data[f"{PREFIX}/actions/runs"] = {"total_count": 1, "workflow_runs": [ci_run(CI_RUN)]}
        run = run_publisher(data)
        self.assertNotIn("unprovided API", run.result.stderr)
        repository_listings = [call for call in run.calls if call.split("?", 1)[0] == f"GET {PREFIX}/actions/runs"
                               and f"head_sha={EVIDENCE}" in call and "event=pull_request" in call]
        self.assertGreaterEqual(len(repository_listings), 1)
        self.assertEqual(mutations(run), [])
        self.assertEqual(app_checks(run.data), [])
        self.assertNotEqual(run.result.returncode, 0)


def existing_authority() -> dict:
    """The landing suite's recorded Security contract success for the fixture tuple."""
    [authority] = [check for check in LANDING.snapshot()[f"{PREFIX}/commits/{Y_HEAD}/check-runs"]["check_runs"]
                   if check["name"] == "Security contract"]
    return authority


def assert_authority_failed_in_place(test: unittest.TestCase, revocation: Revocation, authority: dict) -> None:
    """One PATCH turns the existing authority to failure, keeping its head, external ID and text; nothing is created."""
    test.assertEqual(mutations(revocation), [f"PATCH {PREFIX}/check-runs/{authority['id']}"],
                     revocation.steps[-1].result.stderr)
    [check] = app_checks(revocation.data)
    test.assertEqual((check["id"], *check_identity(check), check["output"]["text"]),
                     (authority["id"], "Security contract", APP, authority["head_sha"], authority["external_id"],
                      "completed", "failure", authority["output"]["text"]))
    test.assertEqual(revocation.steps[-1].result.returncode, 0, revocation.steps[-1].result.stderr)


class ListenerClosedPullRequestPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D): C-P5-2, an existing authority for a closed pull request.

    A failed CI run for the committed E of a closed, unmerged pull request
    fails the existing Security contract success in place: one PATCH, the
    external ID and text preserved, no POST.
    """

    def test_existing_authority_of_a_closed_pull_request_is_failed_in_place(self) -> None:
        event, authority = failed_event(), existing_authority()
        self.assertEqual((authority["head_sha"], authority["external_id"], authority["conclusion"]),
                         (Y_HEAD, AUTHORITY_EXTERNAL_ID, "success"))
        data = listener_fixture(event, checks=(authority,))
        close_pull_request(data, merged=False)
        run = revoke_failed_ci(data, event)
        self.assertNotIn("unprovided API", run.steps[-1].result.stderr)
        self.assertEqual(run.calls[:len(LISTENER_SETUP)], LISTENER_SETUP)
        self.assertEqual(run.outputs["eligible"], "true")
        assert_authority_failed_in_place(self, run, authority)


class ListenerNonCurrentHeadPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D): C-P5-4, a failed run for an E that is not the committed head.

    Pull request N moved from E to a new committed head. A failed CI run on E
    binds existing members only: with none it outputs `eligible=false` and
    writes nothing; with the existing authority it outputs
    `create_missing=false` and fails that authority in place with no POST.
    """

    def test_non_committed_head_binds_existing_authority_only(self) -> None:
        event = failed_event()
        for label, checks in (("no authority", ()), ("existing authority", (existing_authority(),))):
            with self.subTest(case=label):
                data = listener_fixture(event, checks=checks)
                move_pull_request_head(data, MOVED_HEAD, MOVED_MERGE)
                run = revoke_failed_ci(data, event, committed_evidence=MOVED_HEAD)
                self.assertNotIn("unprovided API", run.steps[-1].result.stderr)
                self.assertEqual(run.calls[:len(LISTENER_SETUP)], LISTENER_SETUP)
                if not checks:
                    self.assertEqual(run.outputs, {"eligible": "false"})
                    self.assertEqual(len(run.steps), 2)
                    self.assertEqual(mutations(run), [])
                    self.assertEqual(app_checks(run.data), [])
                else:
                    self.assertEqual((run.outputs["eligible"], run.outputs["create_missing"]), ("true", "false"))
                    assert_authority_failed_in_place(self, run, checks[0])


class DisabledCiBinderPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D): C-P5-5, the landing suite's disabled-CI binder case, run verbatim."""

    def test_disabled_ci_still_binds_exact_bad_attempt_to_existing_authority(self) -> None:
        name = "test_disabled_ci_still_binds_exact_bad_attempt_to_existing_authority"
        result = unittest.TestResult()
        LANDING.DisabledCriticalCiBinderTests(name).run(result)
        self.assertEqual((result.testsRun, result.failures, result.errors, result.skipped), (1, [], [], []))


class ListenerMergedPullRequestPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D): C-P5-6, a pull request that merged with head E.

    A failed CI run for the committed E of a pull request that closed by
    merging with head E, with no existing authority, outputs `eligible=false`
    and writes nothing.
    """

    def test_failed_ci_after_the_pull_request_merged_with_head_e_creates_nothing(self) -> None:
        event = failed_event()
        data = listener_fixture(event)
        close_pull_request(data, merged=True)
        self.assertEqual((data[f"{PREFIX}/pulls/{PR}"]["merged"], data[f"{PREFIX}/pulls/{PR}"]["head"]["sha"]),
                         (True, EVIDENCE))
        run = revoke_failed_ci(data, event)
        self.assertNotIn("unprovided API", run.steps[-1].result.stderr)
        self.assertEqual(run.calls[:len(LISTENER_SETUP)], LISTENER_SETUP)
        self.assertEqual(run.outputs, {"eligible": "false"})
        self.assertEqual(len(run.steps), 2)
        self.assertEqual(mutations(run), [])
        self.assertEqual(app_checks(run.data), [])


class PublisherReopenedPullRequestPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D): C-P5-7, a failure under the test merge before a close and reopen.

    The reopened pull request has a new test merge; CI run 200 failed on E
    under the earlier one. The publisher refuses and tombstones E.
    """

    def test_failure_under_the_earlier_test_merge_denies_after_reopen(self) -> None:
        earlier = LANDING.pull_request_ci_run(200, LANDING.PRIOR_MERGE, conclusion="failure", check_suite_id=400)
        self.assertEqual(earlier["display_title"], f"CI N={PR} E={EVIDENCE} B={BASE} M={LANDING.PRIOR_MERGE}")
        data = publisher_fixture(earlier)
        self.assertEqual((data[f"{PREFIX}/pulls/{PR}"]["state"], data[f"{PREFIX}/git/ref/pull/{PR}/merge"]["object"]["sha"]),
                         ("open", MERGE))
        run = run_publisher(data)
        self.assertNotIn("unprovided API", run.result.stderr)
        self.assertEqual(run.calls[:7], PUBLISHER_SETUP + [CI_HISTORY_GET, CI_CENSUS_GET, *run_reads(200)])
        assert_bad_ci_denial(self, run, [(200, 1, "failure")])


ROUTE_REFUSALS = {
    "missing repository.id": (
        lambda event: event.update(repository={"full_name": REPOSITORY}),
        'test "$(jq -r \'.repository.id\' <<< "${historical_run}")" = "${REPOSITORY_ID}"'),
    "foreign head repository": (
        lambda event: event.update(head_repository=dict(LANDING.FOREIGN_HEAD_REPOSITORY), head_branch="main"),
        'test "$(jq -r \'.head_repository.full_name\' <<< "${historical_run}")" = "${GITHUB_REPOSITORY}"'),
}


class ListenerRunIdentityPreservationTests(unittest.TestCase):
    """Preservation (GREEN at b94eb3788e+D): C-P5-10, a completed run without this repository's identity.

    The listener job resolves the completed run by API identity first
    (REV:174-209). A run missing `repository.id`, or whose head repository is a
    fork, is refused there: no binder runs and nothing is written.
    """

    def test_run_without_this_repository_identity_is_refused_without_a_tombstone(self) -> None:
        for label, (mutate, refused_at) in ROUTE_REFUSALS.items():
            with self.subTest(event_run=label):
                event = failed_event()
                mutate(event)
                run = revoke_failed_ci(listener_fixture(event), event)
                self.assertNotIn("unprovided API", run.steps[-1].result.stderr)
                self.assertEqual(run.calls, [f"GET {PREFIX}/actions/runs/{EVENT_RUN}/attempts/1"])
                self.assertEqual(len(run.steps), 1)
                self.assertEqual(refusals(run.steps[0])[-1], refused_at)
                self.assertEqual(run.outputs, {})
                self.assertEqual(mutations(run), [])
                self.assertEqual(app_checks(run.data), [])


def e_placed_authority() -> dict:
    """A Security contract success on E with the candidate identity of the fixture tuple."""
    text = {"aggregate_check_run_id": "505", "ci_merge_binding": {"artifact_digest": "7" * 64, "artifact_id": "812",
                                                                  "binding_sha256": "9" * 64},
            "identity": IDENTITY, "identity_digest": IDENTITY_DIGEST,
            "merge_observations": {"capture": LANDING.PRIOR_MERGE, "ci": MERGE}, "publication_binding_digest": "2" * 64,
            "required_check_run_ids": {"build": "501", "deny": "504", "msrv": "502", "vet": "503"},
            "schema": "chio.security-check-authority.v3",
            "source_ci": {"run_attempt": "1", "run_id": str(CI_RUN), "workflow_id": str(CI_WORKFLOW)}}
    return {"id": 605, "name": "Security contract", "head_sha": Y_HEAD, "external_id": AUTHORITY_EXTERNAL_ID,
            "status": "completed", "conclusion": "success", "app": dict(APP), "completed_at": "2026-10-06T00:06:00Z",
            "details_url": f"https://github.com/{REPOSITORY}/actions/runs/{FINALIZER_RUN}/attempts/1",
            "output": {"title": "Chio security authority",
                       "summary": f"Dedicated chio-security-authority approval for {AUTHORITY_EXTERNAL_ID}.",
                       "text": json.dumps(text, sort_keys=True, separators=(",", ":"))}}


def assert_e_denial(test: unittest.TestCase, revocation: Revocation, observed: dict[str, str]) -> None:
    test.assertEqual(mutations(revocation), [CHECK_RUN_POST], revocation.steps[-1].result.stderr)
    [check] = app_checks(revocation.data)
    test.assertEqual(check_identity(check), ("Security contract", APP, Y_HEAD, Y_EXTERNAL_ID, "completed", "failure"))
    test.assertEqual(json.loads(check["output"]["text"]), revocation_text("ci-regression", observed))


class ListenerUnavailableTestMergeProspectiveTests(unittest.TestCase):
    """C-P5-3a and C-P5-3b, the denial for E once M_ci and M_cap are unreadable.

    Prospective design control, activated at the P5/P6 boundary; never a genuine Original.
    """

    def test_existing_e_authority_is_failed_in_place_without_the_test_merges(self) -> None:
        event, authority = failed_event(), e_placed_authority()
        data = listener_fixture(event, live_merge=LANDING.REGENERATED_MERGE, checks=(authority,))
        unavailable_test_merges(data)
        run = revoke_failed_ci(data, event)
        self.assertEqual(run.outputs["eligible"], "true")
        assert_authority_failed_in_place(self, run, authority)

    def test_failed_ci_tombstones_e_without_the_test_merges(self) -> None:
        event = failed_event()
        data = listener_fixture(event, live_merge=LANDING.REGENERATED_MERGE)
        unavailable_test_merges(data)
        run = revoke_failed_ci(data, event)
        self.assertEqual((run.outputs["eligible"], run.outputs["create_missing"]), ("true", "true"))
        assert_e_denial(self, run, LISTENER_OBSERVED)


class ListenerMismatchedTitleProspectiveTests(unittest.TestCase):
    """C-P5-9, the denial for E bound by API identity under a mismatched title.

    Prospective design control, activated at the P5/P6 boundary; never a genuine Original.
    """

    def test_failed_ci_with_a_mismatched_title_tombstones_the_api_head(self) -> None:
        event = failed_event(f"CI N={PR} E={MISMATCHED_HEAD} B={BASE} M={MERGE}")
        run = revoke_failed_ci(listener_fixture(event), event)
        self.assertEqual((run.outputs["eligible"], run.outputs["create_missing"]), ("true", "true"))
        assert_e_denial(self, run, {"base_sha": "", "merge_commit_sha": "", "merge_tree_sha": "", "pr_number": ""})


if __name__ == "__main__":
    unittest.main()

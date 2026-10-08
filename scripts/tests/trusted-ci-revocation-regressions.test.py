#!/usr/bin/env python3
"""Exercise the publisher's bad-CI history scan and denial-only revocation offline.

Every case runs the real finalizer and revocation shell from the workflow
definitions through the offline API fakes of the landing regression suite,
with each step's environment resolved from its own `env:` wiring. Only the
GitHub App credential exchange is skipped; the installation token is the
offline check-store token. Original cases describe behaviour the current
producers get wrong; preservation cases pin refusals and denials that must
hold before and after the repairs; prospective cases state an expectation the
current producers have no code path to reach.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
import unittest
from pathlib import Path
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
FINALIZER = "enterprise-evidence-finalizer.yml"
PUBLISHER_SETUP = [f"GET {PREFIX}/contents/.github/workflows/{FINALIZER}?ref={DEFINITION}"] * 2

# The finalizer's Security contract namespace for the fixture tuple: the head
# its App checks are written to and the external ID a denial for E carries.
Y_HEAD, Y_EXTERNAL_ID = MERGE, LANDING.EXTERNAL_ID

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


def publisher_context(committed_evidence: str = EVIDENCE) -> dict[str, str]:
    binding = LANDING.publication_binding()
    authorization = {
        "authorized_source_sha": SOURCE, "ci_aggregate_check_run_id": "505", "ci_run_attempt": "1",
        "ci_run_id": str(CI_RUN), "ci_workflow_id": str(CI_WORKFLOW), "evidence_sha": EVIDENCE,
        "external_id": LANDING.EXTERNAL_ID, "merge_commit_sha": MERGE, "pr_number": str(PR),
        "publication_binding_digest": hashlib.sha256(binding.encode()).hexdigest(),
        "publication_binding_json": binding, "security_definition_sha": DEFINITION,
    }
    return {f"needs.authorize-security-check-publication.outputs.{key}": value for key, value in authorization.items()} | {
        "vars.CHIO_COMMITTED_LINUX_EVIDENCE_SHA": committed_evidence, "github.run_attempt": "1",
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
    return LANDING.pull_request_ci_run(run_id, MERGE, conclusion=conclusion, attempt=attempt, check_suite_id=2 * run_id)


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
    """

    def test_failed_attempt_read_before_a_later_run_read_error_still_denies_the_evidence_head(self) -> None:
        bad, unreadable = ci_run(200, conclusion="failure"), ci_run(202)
        LANDING.assert_authoritative_history(self, bad)
        control = run_publisher(publisher_fixture(bad, unreadable))
        self.assertEqual(control.calls[:12], PUBLISHER_SETUP + [CI_HISTORY_GET, *run_reads(200), *run_reads(CI_RUN),
                                                                  *run_reads(202)])
        assert_bad_ci_denial(self, control, [(200, 1, "failure")])

        data = publisher_fixture(bad, unreadable)
        server_error(data, "actions/runs/202")
        self.assertEqual((data[f"{PREFIX}/actions/runs/200/attempts/1"]["status"],
                          data[f"{PREFIX}/actions/runs/200/attempts/1"]["conclusion"]), ("completed", "failure"))
        run = run_publisher(data)
        self.assertNotIn("unprovided API", run.result.stderr)
        self.assertEqual(run.calls[:10], PUBLISHER_SETUP + [CI_HISTORY_GET, *run_reads(200), *run_reads(CI_RUN),
                                                             f"GET {PREFIX}/actions/runs/202"])
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
    """

    def test_run_read_error_before_the_failed_run_still_denies_the_evidence_head(self) -> None:
        unreadable, bad = ci_run(200), ci_run(202, conclusion="failure")
        LANDING.assert_authoritative_history(self, bad)
        control = run_publisher(publisher_fixture(unreadable, bad))
        self.assertEqual(control.calls[:12], PUBLISHER_SETUP + [CI_HISTORY_GET, *run_reads(200), *run_reads(CI_RUN),
                                                                  *run_reads(202)])
        assert_bad_ci_denial(self, control, [(202, 1, "failure")])

        data = publisher_fixture(unreadable, bad)
        server_error(data, "actions/runs/200")
        self.assertEqual((data[f"{PREFIX}/actions/runs/202/attempts/1"]["status"],
                          data[f"{PREFIX}/actions/runs/202/attempts/1"]["conclusion"]), ("completed", "failure"))
        run = run_publisher(data)
        self.assertNotIn("unprovided API", run.result.stderr)
        self.assertEqual(run.calls[:4], PUBLISHER_SETUP + [CI_HISTORY_GET, f"GET {PREFIX}/actions/runs/200"])
        self.assertEqual(mutations(run), [CHECK_RUN_POST],
                         f"the read of CI run 200 answered HTTP 502 and the step exited {run.result.returncode} before "
                         f"reading failed run 202 (reads: {run.calls[2:]}); refused at: {refusals(run)}")
        assert_bad_ci_denial(self, run, [(202, 1, "failure")])


if __name__ == "__main__":
    unittest.main()

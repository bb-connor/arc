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

import copy
import hashlib
import importlib.util
import json
import re
import sys
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


def run_publisher(data: dict):
    """Run the publish-security-contract step for the sealed binding of PR, E, M and S."""
    binding = LANDING.publication_binding()
    outputs = {
        "authorized_source_sha": SOURCE, "ci_aggregate_check_run_id": "505", "ci_run_attempt": "1",
        "ci_run_id": str(CI_RUN), "ci_workflow_id": str(CI_WORKFLOW), "evidence_sha": EVIDENCE,
        "external_id": LANDING.EXTERNAL_ID, "merge_commit_sha": MERGE, "pr_number": str(PR),
        "publication_binding_digest": hashlib.sha256(binding.encode()).hexdigest(),
        "publication_binding_json": binding, "security_definition_sha": DEFINITION,
    }
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


def run_revoker(data: dict, event_name: str):
    """Run the revoke-security-contract step for a bound denial of PR, E, M and S."""
    manual = event_name == "workflow_dispatch"
    outputs = {
        "authorized_source_sha": SOURCE, "base_sha": BASE, "create_missing": "true", "evidence_sha": EVIDENCE,
        "merge_commit_sha": MERGE, "merge_tree_sha": TREE, "pr_number": str(PR),
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


if __name__ == "__main__":
    unittest.main()

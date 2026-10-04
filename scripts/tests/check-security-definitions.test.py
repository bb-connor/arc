#!/usr/bin/env python3
"""Exercise trusted workflow Bash without foundation source or GitHub credentials.

Requires Python 3.12+, PyYAML 6.0.3, Bash, jq, and GNU coreutils. All API calls
below use local fixtures. These tests do not qualify native execution or hosted
App provisioning. Run: python3 scripts/tests/check-security-definitions.test.py
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
FINALIZER = "enterprise-evidence-finalizer.yml"
REVOKER = "security-contract-revocation.yml"
BASE = "1" * 40
EVIDENCE = "2" * 40
MERGE = "3" * 40
TREE = "4" * 40
OTHER = "5" * 40


def workflow_step(workflow: str, job: str, name: str) -> str:
    document = yaml.load(
        (ROOT / ".github/workflows" / workflow).read_text(), Loader=yaml.BaseLoader
    )
    matches = [
        step for step in document["jobs"][job]["steps"] if step.get("name") == name
    ]
    if len(matches) != 1 or not isinstance(matches[0].get("run"), str):
        raise AssertionError(f"missing unique run step: {workflow}/{job}/{name}")
    return matches[0]["run"]


def shell_function(body: str, name: str) -> str:
    matches = re.findall(rf"(?ms)^{re.escape(name)}\(\) \{{\n.*?^\}}$", body)
    if len(matches) != 1:
        raise AssertionError(f"missing unique Bash function: {name}")
    return matches[0]


def shell_region(body: str, start: str, end: str) -> str:
    if body.count(start) != 1:
        raise AssertionError(f"missing unique Bash region start: {start}")
    remainder = body.split(start, 1)[1]
    if end not in remainder:
        raise AssertionError(f"missing Bash region end: {end}")
    return start + remainder.split(end, 1)[0]


def labels_digest(labels: list[str]) -> str:
    return hashlib.sha256(
        json.dumps(sorted(labels), ensure_ascii=False, separators=(",", ":")).encode()
    ).hexdigest()


PUBLICATION_API = r"""
curl() {
  local url="${@: -1}" method=GET
  while test "$#" -gt 0; do
    if test "$1" = '--request'; then method="$2"; fi
    shift
  done
  case "${method} ${url}" in
    'GET https://api.github.com/repos/bb-connor/arc/pulls/1160')
      if test -f check-posted; then
        printf '%s\n' "${MOCK_AFTER_PR}"
      else
        printf '%s\n' "${MOCK_PR}"
      fi ;;
    'GET https://api.github.com/repos/bb-connor/arc/git/ref/pull/1160/merge')
      printf '%s\n' "${MOCK_REF}" ;;
    "GET https://api.github.com/repos/bb-connor/arc/git/commits/${MERGE_COMMIT_SHA}")
      printf '%s\n' "${MOCK_COMMIT}" ;;
    'POST https://api.github.com/repos/bb-connor/arc/check-runs')
      printf 'posted\n' > check-posted
      printf '{"id":99}\n' ;;
    *) printf 'unexpected fixture API request\n' >&2; return 22 ;;
  esac
}
"""

APP_API = r"""
date() {
  if test "$*" = '+%s'; then printf '2000\n'; else command date "$@"; fi
}
curl() {
  local url="${@: -1}" authorization='' method=GET request=''
  while test "$#" -gt 0; do
    case "$1" in
      -H) if [[ "${2-}" == 'Authorization: Bearer '* ]]; then authorization="$2"; fi ;;
      --request) method="$2" ;;
      --data-binary) request="$2" ;;
    esac
    shift
  done
  if test "$url" = 'https://api.github.com/installation/repositories?per_page=100'; then
    test "$method" = GET || return 22
    test "$authorization" = 'Authorization: Bearer ghs_fixture_security_authority_token' || return 22
    printf '%s\n' "$MOCK_REPOSITORIES"
    return
  fi
  test "$authorization" = 'Authorization: Bearer fixture-jwt' || return 22
  case "${method} ${url}" in
    'GET https://api.github.com/app') printf '%s\n' "$MOCK_APP" ;;
    'GET https://api.github.com/app/installations/7') printf '%s\n' "$MOCK_INSTALLATION" ;;
    'POST https://api.github.com/app/installations/7/access_tokens')
      test "$(jq -cS . <<< "$request")" = '{"permissions":{"checks":"write"}}' || return 22
      printf 'requested\n' > token-requested
      printf '%s\n' "$MOCK_TOKEN" ;;
    *) printf 'unexpected fixture API request\n' >&2; return 22 ;;
  esac
}
"""

CI_CATALOG_API = r"""
catalog_request() {
  local url="${@: -1}" count=0 reply
  case "$url" in
    */actions/workflows/ci.yml/runs\?*)
      if test -f catalog-calls; then read -r count < catalog-calls; fi
      printf '%s\n' "$((count + 1))" > catalog-calls
      reply="$(jq -c --argjson index "$count" '.[$index] // .[-1]' <<< "$MOCK_PAGES")"
      jq -r '.body | if type == "string" then . else tojson end' <<< "$reply"
      return "$(jq -r '.exit_code // 0' <<< "$reply")" ;;
    */actions/runs/1)
      printf '%s\n' "$MOCK_RUN" ;;
    */actions/runs/1/attempts/*)
      if test -n "${MOCK_ATTEMPTS-}"; then
        jq -c --arg attempt "${url##*/}" '.[$attempt]' <<< "$MOCK_ATTEMPTS"
      else
        printf '%s\n' "$MOCK_RUN"
      fi ;;
    *) printf 'unexpected fixture CI API request\n' >&2; return 22 ;;
  esac
}
curl() { catalog_request "$@"; }
gh() { catalog_request "$@"; }
"""


class DefinitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.publisher = workflow_step(
            FINALIZER, "publish-security-contract", "Reconcile exact five-context merge authority"
        )
        cls.revalidate = shell_function(cls.publisher, "revalidate_live_publication_head")
        cls.reconcile = shell_function(cls.publisher, "reconcile_bad_ci")
        reconcile_body = textwrap.dedent("\n".join(cls.reconcile.splitlines()[1:-1]))
        wait_body = workflow_step(
            FINALIZER, "authorize-security-check-publication", "Authenticate exact successful current CI run"
        )
        cls.catalog_helpers = {
            "publisher": shell_function(reconcile_body, "list_matching_ci_runs"),
            "wait-for-ci": shell_function(wait_body, "list_matching_ci_runs"),
        }
        cls.wait_for_ci = shell_region(wait_body, "for _ in $(seq 1 480); do\n", "ci_run_id=")
        cls.app_programs = {}
        for workflow, job, name in (
            (FINALIZER, "publish-security-contract", "Reconcile exact five-context merge authority"),
            (REVOKER, "revoke-security-contract", "Revoke exact Actions mirrors and dedicated App namespace"),
        ):
            body = workflow_step(workflow, job, name)
            end = 'test "$(jq -r \'.repositories[0].full_name\' <<< "${repositories}")" = "${GITHUB_REPOSITORY}"'
            cls.app_programs[workflow] = shell_region(body, 'app="$(', end) + end

    def run_shell(self, program: str, environment: dict[str, str]) -> tuple[int, str, set[str]]:
        with tempfile.TemporaryDirectory(prefix="chio-security-definitions-") as raw:
            env = {
                "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                "GITHUB_OUTPUT": str(Path(raw) / "output"),
                "GITHUB_STEP_SUMMARY": str(Path(raw) / "summary"),
            }
            env.update(environment)
            result = subprocess.run(
                ["/bin/bash", "--noprofile", "--norc", "-c", "set -euo pipefail\nshopt -s inherit_errexit\n" + program],
                cwd=raw, env=env, capture_output=True, text=True, timeout=15,
            )
            files = {path.name for path in Path(raw).iterdir()}
        return result.returncode, result.stderr, files

    def publication_fixture(self, labels: list[str] | None = None) -> dict:
        names = labels or []
        return {
            "binding": {
                "base": {"repository": "bb-connor/arc", "ref": "main", "sha": BASE},
                "merge_commit_sha": MERGE, "merge_tree_sha": TREE,
                "labels_digest": labels_digest(names),
            },
            "pr": {
                "state": "open", "labels": [{"name": name} for name in names],
                "head": {"repo": {"full_name": "bb-connor/arc"}, "sha": EVIDENCE},
                "base": {"repo": {"full_name": "bb-connor/arc"}, "ref": "main", "sha": BASE},
            },
            "ref": {"ref": "refs/pull/1160/merge", "object": {"type": "commit", "sha": MERGE}},
            "commit": {"parents": [{"sha": BASE}, {"sha": EVIDENCE}], "tree": {"sha": TREE}},
        }

    def run_publication(self, fixture: dict, *, after: dict | None = None, write: bool = False) -> tuple[int, str, set[str]]:
        env = {
            "GITHUB_REPOSITORY": "bb-connor/arc", "GH_TOKEN": "fixture-no-credential",
            "PR_NUMBER": "1160", "EVIDENCE_SHA": EVIDENCE, "MERGE_COMMIT_SHA": MERGE,
            "canonical_binding": json.dumps(fixture["binding"]),
            "MOCK_PR": json.dumps(fixture["pr"]), "MOCK_AFTER_PR": json.dumps(after or fixture["pr"]),
            "MOCK_REF": json.dumps(fixture["ref"]), "MOCK_COMMIT": json.dumps(fixture["commit"]),
        }
        program = PUBLICATION_API + self.revalidate + "\n"
        if write:
            region = shell_region(
                self.publisher,
                "revalidate_live_publication_head\nauthority_created=false\n",
                "check_run_id=",
            )
            env.update({"existing_authority_match_count": "0", "installation_token": "fixture-token", "check_payload": "{}"})
            program += "require_publishable_ci() { return 0; }\n" + region
        else:
            program += "revalidate_live_publication_head\n"
        return self.run_shell(program, env)

    def test_publisher_accepts_unchanged_merge_and_sorted_labels(self) -> None:
        fixture = self.publication_fixture(["zeta", "alpha"])
        fixture["pr"]["labels"].reverse()
        code, error, _ = self.run_publication(fixture)
        self.assertEqual(code, 0, error)

    def test_publisher_rejects_late_refresh_label(self) -> None:
        fixture = self.publication_fixture()
        fixture["pr"]["labels"] = [{"name": "refresh-linux-evidence"}]
        self.assertNotEqual(self.run_publication(fixture)[0], 0)

    def test_publisher_rejects_late_unrelated_label(self) -> None:
        fixture = self.publication_fixture()
        fixture["pr"]["labels"] = [{"name": "unrelated"}]
        self.assertNotEqual(self.run_publication(fixture)[0], 0)

    def test_publisher_rejects_refresh_mode_even_if_digest_matches(self) -> None:
        self.assertNotEqual(self.run_publication(self.publication_fixture(["refresh-linux-evidence"]))[0], 0)

    def test_publisher_rejects_head_base_and_merge_drift(self) -> None:
        changes = (
            (("pr", "state"), "closed"),
            (("pr", "head", "sha"), OTHER),
            (("pr", "head", "repo", "full_name"), "other/arc"),
            (("pr", "base", "sha"), OTHER),
            (("pr", "base", "ref"), "other"),
            (("pr", "base", "repo", "full_name"), "other/arc"),
            (("ref", "ref"), "refs/pull/2/merge"),
            (("ref", "object", "sha"), OTHER),
            (("ref", "object", "type"), "tag"),
            (("commit", "parents"), [{"sha": EVIDENCE}, {"sha": BASE}]),
            (("commit", "parents"), [{"sha": BASE}, {"sha": EVIDENCE}, {"sha": OTHER}]),
            (("commit", "tree", "sha"), OTHER),
        )
        for keys, value in changes:
            with self.subTest(keys=keys):
                fixture = self.publication_fixture()
                target = fixture
                for key in keys[:-1]:
                    target = target[key]
                target[keys[-1]] = value
                self.assertNotEqual(self.run_publication(fixture)[0], 0)

    def test_publication_write_rechecks_late_labels(self) -> None:
        fixture = self.publication_fixture()
        after = copy.deepcopy(fixture["pr"])
        after["labels"] = [{"name": "refresh-linux-evidence"}]
        code, _, files = self.run_publication(fixture, after=after, write=True)
        self.assertIn("check-posted", files)
        self.assertNotEqual(code, 0, "post-write label drift must fail the finalizer for revocation")

    def test_publication_write_accepts_unchanged_state(self) -> None:
        code, error, files = self.run_publication(self.publication_fixture(), write=True)
        self.assertEqual(code, 0, error)
        self.assertIn("check-posted", files)

    def test_publication_refuses_write_after_label_drift(self) -> None:
        fixture = self.publication_fixture()
        fixture["pr"]["labels"] = [{"name": "refresh-linux-evidence"}]
        code, _, files = self.run_publication(fixture, write=True)
        self.assertNotEqual(code, 0)
        self.assertNotIn("check-posted", files)

    def app_fixture(self) -> dict:
        permissions = {"checks": "write", "metadata": "read", "statuses": "write"}
        return {
            "app": {"id": 42, "slug": "chio-security-authority", "owner": {"login": "bb-connor"}, "permissions": permissions.copy()},
            "installation": {"id": 7, "app_id": 42, "app_slug": "chio-security-authority", "account": {"login": "bb-connor"}, "repository_selection": "selected", "permissions": permissions.copy()},
            "token": {"token": "ghs_fixture_security_authority_token", "permissions": {"checks": "write", "metadata": "read"}, "expires_at": "1970-01-01T01:33:20Z"},
            "repositories": {"total_count": 1, "repositories": [{"full_name": "bb-connor/arc"}]},
        }

    def run_app(self, workflow: str, fixture: dict) -> tuple[int, str, set[str]]:
        env = {
            "SECURITY_APP_ID": "42", "SECURITY_APP_INSTALLATION_ID": "7",
            "GITHUB_REPOSITORY_OWNER": "bb-connor", "GITHUB_REPOSITORY": "bb-connor/arc",
            "jwt": "fixture-jwt", "now_epoch": "1995", "private_key": "unused-fixture-key",
        }
        env.update({"MOCK_" + key.upper(): json.dumps(value) for key, value in fixture.items()})
        return self.run_shell(APP_API + self.app_programs[workflow], env)

    def test_app_bootstraps_with_jwt_metadata_and_delayed_token(self) -> None:
        for workflow in self.app_programs:
            with self.subTest(workflow=workflow):
                code, error, files = self.run_app(workflow, self.app_fixture())
                self.assertEqual(code, 0, error)
                self.assertIn("token-requested", files)

    def test_app_rejects_wrong_metadata_before_token_issuance(self) -> None:
        changes = (
            (("app", "id"), 99), (("app", "slug"), "other-app"),
            (("app", "owner", "login"), "other"),
            (("app", "permissions"), {"checks": "write", "metadata": "read"}),
            (("installation", "id"), 99), (("installation", "app_id"), 99),
            (("installation", "app_slug"), "other-app"),
            (("installation", "account", "login"), "other"),
            (("installation", "repository_selection"), "all"),
            (("installation", "permissions"), {"checks": "write", "metadata": "read", "statuses": "write", "contents": "read"}),
        )
        for workflow in self.app_programs:
            for keys, value in changes:
                with self.subTest(workflow=workflow, keys=keys):
                    fixture = self.app_fixture()
                    target = fixture
                    for key in keys[:-1]:
                        target = target[key]
                    target[keys[-1]] = value
                    code, _, files = self.run_app(workflow, fixture)
                    self.assertNotEqual(code, 0)
                    self.assertNotIn("token-requested", files)

    def test_app_rejects_wrong_token_scope_lifetime_or_repository(self) -> None:
        changes = (
            (("token", "permissions"), {"checks": "write", "statuses": "write"}),
            (("token", "permissions"), {"checks": "write", "contents": "read"}),
            (("token", "permissions"), {"checks": "read"}),
            (("token", "token"), "invalid"), (("token", "token"), ""),
            (("token", "expires_at"), "1970-01-01T00:33:20Z"),
            (("token", "expires_at"), "1970-01-01T01:33:21Z"),
            (("repositories", "total_count"), 2),
            (("repositories", "repositories"), [{"full_name": "other/arc"}]),
            (("repositories", "repositories"), [{"full_name": "bb-connor/arc"}, {"full_name": "other/arc"}]),
        )
        for workflow in self.app_programs:
            for keys, value in changes:
                with self.subTest(workflow=workflow, keys=keys, value=value):
                    fixture = self.app_fixture()
                    fixture[keys[0]][keys[1]] = value
                    self.assertNotEqual(self.run_app(workflow, fixture)[0], 0)

    def test_committed_evidence_cannot_bootstrap_from_source_only(self) -> None:
        body = workflow_step("enterprise-hardening.yml", "committed-linux-evidence", "Bind required committed evidence")
        for evidence, accepted in (("", False), ("invalid", False), (BASE, False), (EVIDENCE, True)):
            with self.subTest(evidence=evidence):
                code, _, files = self.run_shell(body, {"AUTHORIZED_SOURCE_SHA": BASE, "EVIDENCE_SHA": evidence})
                self.assertEqual(code == 0, accepted)
                self.assertEqual("output" in files, accepted)

    def test_committed_evidence_requires_explicit_verifier_success(self) -> None:
        body = workflow_step("enterprise-hardening.yml", "committed-linux-evidence", "Require committed Linux evidence verification")
        for verified in ("", "false", "true"):
            with self.subTest(verified=verified):
                code, _, _ = self.run_shell(body, {"VERIFIED": verified})
                self.assertEqual(code == 0, verified == "true")

    def test_capture_rechecks_label_digest_and_mode(self) -> None:
        body = workflow_step("enterprise-linux-capture.yml", "authorize-capture", "Revalidate live merge authorization")
        region = shell_region(body, "stable_labels_json=", "\nstable_merge_ref=")
        cases = (
            ([], [], "enforcement", True),
            ([], ["refresh-linux-evidence"], "enforcement", False),
            (["refresh-linux-evidence"], [], "refresh", False),
            ([], ["unrelated"], "enforcement", False),
            ([], [], "refresh", False),
        )
        for initial, live, mode, accepted in cases:
            with self.subTest(initial=initial, live=live, mode=mode):
                code, _, _ = self.run_shell(region, {
                    "stable_pr": json.dumps({"labels": [{"name": name} for name in live]}),
                    "INPUT_LABELS_DIGEST": labels_digest(initial), "INPUT_MODE": mode,
                })
                self.assertEqual(code == 0, accepted)

    def ci_run_fixture(self, identifier: int = 1) -> dict:
        return {
            "id": identifier, "name": "CI", "path": ".github/workflows/ci.yml",
            "event": "pull_request", "workflow_id": 77,
            "display_title": f"CI N=1160 E={EVIDENCE} B={BASE} M={MERGE}",
            "head_sha": EVIDENCE, "head_branch": "foundation",
            "head_repository": {"full_name": "bb-connor/arc"},
            "run_attempt": 1, "status": "completed", "conclusion": "success",
        }

    def catalog_environment(self, pages: list[dict], run: dict | None = None) -> dict[str, str]:
        name = f"CI N=1160 E={EVIDENCE} B={BASE} M={MERGE}"
        return {
            "GH_TOKEN": "fixture-no-credential", "GITHUB_REPOSITORY": "bb-connor/arc",
            "EVIDENCE_SHA": EVIDENCE, "BASE_SHA": BASE, "MERGE_COMMIT_SHA": MERGE,
            "PR_NUMBER": "1160", "CI_WORKFLOW_ID": "77", "CI_RUN_ID": "1", "HEAD_REF": "foundation",
            "expected_run_name": name, "expected_ci_run_name": name,
            "canonical_binding": json.dumps({"base": {"sha": BASE}}),
            "MOCK_PAGES": json.dumps(pages), "MOCK_RUN": json.dumps(run or self.ci_run_fixture()),
        }

    def run_catalog(self, helper: str, pages: list[dict], *, conditional: bool = True) -> tuple[int, str, set[str]]:
        call = 'matching_ci_runs="$(list_matching_ci_runs)"\n'
        if conditional:
            call = 'if ! matching_ci_runs="$(list_matching_ci_runs)"; then exit 1; fi\n'
        return self.run_shell(
            CI_CATALOG_API + self.catalog_helpers[helper] + "\n" + call + "printf accepted > accepted\n",
            self.catalog_environment(pages),
        )

    def malformed_catalogs(self) -> dict[str, list[dict]]:
        good = self.ci_run_fixture()
        other = self.ci_run_fixture(2)
        other["display_title"] = "unrelated CI"
        full_page = [good] + [dict(other, id=index) for index in range(2, 101)]
        last = dict(other, id=101)
        return {
            "duplicate unrelated run IDs": [{"body": {"total_count": 3, "workflow_runs": [good, other, other]}}],
            "duplicate across pages": [
                {"body": {"total_count": 101, "workflow_runs": full_page}},
                {"body": {"total_count": 101, "workflow_runs": [other]}},
            ],
            "unstable total": [
                {"body": {"total_count": 101, "workflow_runs": full_page}},
                {"body": {"total_count": 102, "workflow_runs": [last]}},
            ],
            "short nonterminal page": [
                {"body": {"total_count": 2, "workflow_runs": [good]}},
                {"body": {"total_count": 2, "workflow_runs": [other]}},
            ],
            "oversized terminal page": [{"body": {"total_count": 101, "workflow_runs": full_page + [last]}}],
            "string total": [{"body": {"total_count": "1", "workflow_runs": [good]}}],
            "null run ID": [{"body": {"total_count": 2, "workflow_runs": [good, dict(other, id=None)]}}],
            "non-array catalog": [{"body": {"total_count": 1, "workflow_runs": good}}],
            "malformed JSON": [{"body": "{"}],
            "API failure with body": [{"body": {"total_count": 1, "workflow_runs": [good]}, "exit_code": 22}],
            "fallback API failure with body": [
                {"body": {"total_count": 1000}},
                {"body": {"total_count": 1, "workflow_runs": [good]}, "exit_code": 22},
            ],
            "later page API failure with body": [
                {"body": {"total_count": 101, "workflow_runs": full_page}},
                {"body": {"total_count": 101, "workflow_runs": [last]}, "exit_code": 22},
            ],
        }

    def test_ci_catalog_rejects_bad_pages_inside_conditional_calls(self) -> None:
        for helper in self.catalog_helpers:
            for label, pages in self.malformed_catalogs().items():
                with self.subTest(helper=helper, label=label):
                    code, _, files = self.run_catalog(helper, pages)
                    self.assertNotEqual(code, 0, "conditional helper accepted an invalid CI catalog")
                    self.assertNotIn("accepted", files)

    def test_ci_catalog_duplicate_rejection_is_not_errexit_dependent(self) -> None:
        pages = self.malformed_catalogs()["duplicate unrelated run IDs"]
        for helper in self.catalog_helpers:
            with self.subTest(helper=helper):
                self.assertNotEqual(self.run_catalog(helper, pages, conditional=False)[0], 0)

    def test_ci_catalog_accepts_valid_and_fallback_pages(self) -> None:
        good = self.ci_run_fixture()
        page = {"body": {"total_count": 1, "workflow_runs": [good]}}
        full_page = [self.ci_run_fixture(index) for index in range(1, 101)]
        two_pages = [
            {"body": {"total_count": 101, "workflow_runs": full_page}},
            {"body": {"total_count": 101, "workflow_runs": [self.ci_run_fixture(101)]}},
        ]
        for helper in self.catalog_helpers:
            for label, pages in (
                ("one page", [page]),
                ("two pages", two_pages),
                ("filtered catalog limit fallback", [{"body": {"total_count": 1000}}, page]),
                ("empty catalog", [{"body": {"total_count": 0, "workflow_runs": []}}]),
            ):
                with self.subTest(helper=helper, label=label):
                    code, error, files = self.run_catalog(helper, pages)
                    self.assertEqual(code, 0, error)
                    self.assertIn("accepted", files)

    def test_publisher_does_not_accept_ambiguous_ci_catalog(self) -> None:
        good = self.ci_run_fixture()
        valid = [{"body": {"total_count": 1, "workflow_runs": [good]}}]
        duplicate = self.malformed_catalogs()["duplicate unrelated run IDs"]
        for label, pages, accepted in (
            ("valid", valid, True),
            ("duplicate unrelated IDs", duplicate, False),
            ("duplicate stability scan", (valid + duplicate) * 3, False),
            ("retry after rejected catalog", duplicate + valid, True),
        ):
            with self.subTest(label=label):
                code, error, files = self.run_shell(
                    CI_CATALOG_API + self.reconcile + '\nreconcile_bad_ci\ntest "$bad_ci_observed" = false\nprintf accepted > accepted\n',
                    self.catalog_environment(pages),
                )
                self.assertEqual(code == 0, accepted, error)
                self.assertEqual("accepted" in files, accepted)

    def test_wait_for_ci_retries_rejected_catalogs(self) -> None:
        valid = [{"body": {"total_count": 1, "workflow_runs": [self.ci_run_fixture()]}}]
        duplicate = self.malformed_catalogs()["duplicate unrelated run IDs"]
        # Bound only the polling budget and delay; execute the actual caller loop.
        budget = "seq() { printf '1\\n2\\n3\\n'; }\nsleep() { :; }\nci_run=''\n"
        for label, pages, accepted in (
            ("valid", valid, True),
            ("duplicate", duplicate, False),
            ("retry after rejected catalog", duplicate + valid, True),
        ):
            with self.subTest(label=label):
                code, error, files = self.run_shell(
                    CI_CATALOG_API + self.catalog_helpers["wait-for-ci"] + "\n" + budget
                    + self.wait_for_ci + "printf accepted > accepted\n",
                    self.catalog_environment(pages),
                )
                self.assertEqual(code == 0, accepted, error)
                self.assertEqual("accepted" in files, accepted)

    def test_bad_ci_still_requests_all_five_revocations(self) -> None:
        for conclusion in ("failure", "cancelled", "timed_out", "older failed attempt"):
            with self.subTest(conclusion=conclusion):
                run = dict(self.ci_run_fixture(), conclusion=conclusion)
                if conclusion == "older failed attempt":
                    run.update(conclusion="success", run_attempt=2)
                env = self.catalog_environment([{"body": {"total_count": 1, "workflow_runs": [run]}}], run)
                env.update({"installation_token": "fixture-token", "SECURITY_APP_ID": "77", "EXTERNAL_ID": "fixture-binding"})
                if conclusion == "older failed attempt":
                    env["MOCK_ATTEMPTS"] = json.dumps({
                        "1": dict(self.ci_run_fixture(), conclusion="failure"), "2": run,
                    })
                # Check reconciliation requests; real check writes remain a hosted boundary.
                normalizer = 'normalize_bad_ci_namespace() { printf "%s\\n" "$4" >> normalized; }\n'
                code, error, files = self.run_shell(
                    CI_CATALOG_API + self.reconcile + "\n" + normalizer
                    + 'reconcile_bad_ci\ntest "$bad_ci_observed" = true\n'
                    + 'test "$(sort -u normalized | wc -l)" = 5\n'
                    + 'test "$bad_ci_create_missing" = false\nprintf revoked > revoked\n',
                    env,
                )
                self.assertEqual(code, 0, error)
                self.assertIn("revoked", files)


if __name__ == "__main__":
    unittest.main(verbosity=2)

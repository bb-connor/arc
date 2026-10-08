#!/usr/bin/env python3
"""Exercise trusted CI producers and the real landing audit with offline APIs."""

from __future__ import annotations

import copy
import base64
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from typing import NamedTuple


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "security_ci_contract", ROOT / "scripts/check-security-ci-contract.py"
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load the source contract checker")
CHECKER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = CHECKER
SPEC.loader.exec_module(CHECKER)

REPOSITORY = "bb-connor/arc"
PR = 1160
SOURCE, EVIDENCE, BASE, MERGE, PROTECTED, DEFINITION = (
    "a" * 40, "b" * 40, "c" * 40, "d" * 40, "e" * 40, "f" * 40
)
TREE = "0" * 40
APP_ID = 4398745
CI_RUN, FINALIZER_RUN = 201, 301
CI_WORKFLOW, FINALIZER_WORKFLOW = 101, 102
EXTERNAL_ID = f"arc:{PR}:{EVIDENCE}:{MERGE}:{SOURCE}"
ORDINARY = (
    ("Build, lint, test", "build"),
    ("MSRV build and test", "msrv"),
    ("cargo-vet (locked supply-chain audit)", "vet"),
    ("cargo-deny (supply-chain bans/advisories/licenses)", "deny"),
)


def workflow(name: str) -> dict:
    return CHECKER.load_workflow(ROOT / ".github/workflows" / name)


class CriticalCiProducerTests(unittest.TestCase):
    def test_label_removal_does_not_start_another_critical_run(self) -> None:
        self.assertNotIn("unlabeled", workflow("ci.yml")["on"]["pull_request"]["types"])

    def test_critical_callers_cannot_cancel_a_same_tuple_run(self) -> None:
        for name in ("ci.yml", "enterprise-hardening.yml", "chio-tee-fips.yml",
                     "apalache-safety.yml", "threat-model-coverage.yml"):
            with self.subTest(workflow=name):
                concurrency = workflow(name).get("concurrency")
                if concurrency is not None:
                    self.assertEqual(concurrency.get("cancel-in-progress"), "false")
                    self.assertIn("${{ github.run_id }}", concurrency["group"])
                    self.assertIn("${{ github.run_attempt }}", concurrency["group"])

    def test_nextest_has_its_own_truthful_advisory_result(self) -> None:
        self.assertNotIn("nextest-security", workflow("ci.yml")["jobs"])
        advisory = workflow("security-nextest-advisory.yml")
        self.assertEqual(advisory["permissions"], {"contents": "read"})
        job = advisory["jobs"]["nextest-security"]
        self.assertNotIn("continue-on-error", job)
        self.assertNotIn("environment", job)
        for step in job["steps"]:
            self.assertNotIn("continue-on-error", step)

    def test_every_original_critical_dependency_still_requires_success(self) -> None:
        aggregate = workflow("ci.yml")["jobs"]["security-contract-required"]
        dependencies = [
            "check", "kani-public-pr", "formal-proof-contract", "apalache-full-contract",
            "threat-model-coverage-contract", "msrv", "cargo-vet", "cargo-deny",
            "enterprise-security-contract", "nonce-fips-contract",
        ]
        self.assertEqual(aggregate["needs"], dependencies)
        body = aggregate["steps"][0]["run"]
        for name in dependencies:
            self.assertIn(f"test '${{{{ needs.{name}.result }}}}' = success", body)
        self.assertEqual(
            workflow("security-contract-revocation.yml")["on"]["workflow_run"]["workflows"],
            ["CI", "Enterprise evidence finalizer"],
        )


def snapshot() -> dict[str, dict]:
    prefix = f"repos/{REPOSITORY}"
    repository = {"id": 1195888645, "full_name": REPOSITORY}
    ci = {
        "id": CI_RUN, "workflow_id": CI_WORKFLOW, "path": ".github/workflows/ci.yml",
        "display_title": f"CI N={PR} E={EVIDENCE} B={BASE} M={MERGE}",
        "name": "CI", "event": "pull_request", "head_sha": EVIDENCE,
        "repository": repository, "head_repository": repository, "run_attempt": 1,
        "status": "completed", "conclusion": "success", "check_suite_id": 401,
    }
    finalizer = {
        "id": FINALIZER_RUN, "workflow_id": FINALIZER_WORKFLOW,
        "path": ".github/workflows/enterprise-evidence-finalizer.yml",
        "display_title": f"Enterprise evidence finalizer N={PR} E={EVIDENCE} M={MERGE} S={SOURCE} K={'1' * 64}",
        "event": "workflow_dispatch", "head_sha": DEFINITION, "head_branch": "main",
        "repository": repository, "head_repository": repository, "run_attempt": 1,
        "status": "completed", "conclusion": "success",
        "actor": {"login": "github-actions[bot]"},
        "triggering_actor": {"login": "github-actions[bot]"},
        "created_at": "2026-10-06T00:00:00Z", "updated_at": "2026-10-06T00:05:00Z",
    }
    identity = {"pr_number": str(PR), "authorized_source_sha": SOURCE,
                "evidence_sha": EVIDENCE, "merge_commit_sha": MERGE}
    source_ci = {"run_id": str(CI_RUN), "run_attempt": "1", "workflow_id": str(CI_WORKFLOW)}
    checks, jobs = [], []
    data = {
        prefix: repository | {"default_branch": "main"},
        f"{prefix}/pulls/{PR}": {
            "number": PR, "state": "closed", "merged": True,
            "merged_at": "2026-10-06T00:10:00Z", "merge_commit_sha": PROTECTED,
            "head": {"sha": EVIDENCE, "repo": repository},
            "base": {"ref": "main", "repo": repository},
        },
        f"{prefix}/git/commits/{PROTECTED}": {
            "sha": PROTECTED, "parents": [{"sha": BASE}, {"sha": EVIDENCE}],
            "tree": {"sha": TREE},
        },
        f"{prefix}/git/commits/{MERGE}": {
            "sha": MERGE, "parents": [{"sha": BASE}, {"sha": EVIDENCE}],
            "tree": {"sha": TREE},
        },
        f"{prefix}/git/ref/heads/main": {"ref": "refs/heads/main", "object": {"type": "commit", "sha": PROTECTED}},
        f"{prefix}/compare/{PROTECTED}...{PROTECTED}": {"status": "identical", "behind_by": 0, "merge_base_commit": {"sha": PROTECTED}},
        f"{prefix}/compare/{SOURCE}...{EVIDENCE}": {"status": "ahead", "behind_by": 0, "merge_base_commit": {"sha": SOURCE}},
        f"{prefix}/actions/workflows/ci.yml": {"id": CI_WORKFLOW, "path": ".github/workflows/ci.yml", "state": "active"},
        f"{prefix}/actions/workflows/enterprise-evidence-finalizer.yml": {"id": FINALIZER_WORKFLOW, "path": ".github/workflows/enterprise-evidence-finalizer.yml", "state": "active"},
        f"{prefix}/actions/workflows/ci.yml/runs": {"total_count": 1, "workflow_runs": [ci]},
        f"{prefix}/actions/runs/{CI_RUN}": ci,
        f"{prefix}/actions/runs/{CI_RUN}/attempts/1": copy.deepcopy(ci),
        f"{prefix}/actions/runs/{FINALIZER_RUN}/attempts/1": finalizer,
        f"{prefix}/actions/runs/{FINALIZER_RUN}": copy.deepcopy(finalizer),
        f"{prefix}/actions/workflows/enterprise-evidence-finalizer.yml/runs": {
            "total_count": 1, "workflow_runs": [copy.deepcopy(finalizer)]
        },
        f"{prefix}/commits/{PROTECTED}/check-runs": {"total_count": 0, "check_runs": []},
    }
    for offset, (name, suffix) in enumerate(ORDINARY, 1):
        original = {
            "id": 500 + offset, "name": name, "head_sha": EVIDENCE,
            "status": "completed", "conclusion": "success",
            "app": {"id": 15368, "slug": "github-actions"}, "check_suite": {"id": 401, "head_sha": EVIDENCE},
        }
        data[f"{prefix}/check-runs/{original['id']}"] = original
        jobs.append({
            "id": 700 + offset, "name": name, "run_id": CI_RUN, "head_sha": EVIDENCE,
            "status": "completed", "conclusion": "success",
            "check_run_url": f"https://api.github.com/{prefix}/check-runs/{original['id']}",
        })
        text = {"schema": "chio.security-check-authority.v2", "identity": identity,
                "source_ci": source_ci, "source_check": {"check_run_id": str(original["id"]), "name": name}}
        checks.append({
            "id": 600 + offset, "name": f"Security mirror / {name}", "head_sha": MERGE,
            "status": "completed", "conclusion": "success", "external_id": f"{EXTERNAL_ID}:actions:{suffix}",
            "app": {"id": 15368, "slug": "github-actions"}, "output": {"text": json.dumps(text)},
            "completed_at": "2026-10-06T00:06:00Z",
        })
    checks.append({
        "id": 605, "name": "Security contract", "head_sha": MERGE,
        "status": "completed", "conclusion": "success", "external_id": EXTERNAL_ID,
        "app": {"id": APP_ID, "slug": "chio-security-authority"},
        "details_url": f"https://github.com/{REPOSITORY}/actions/runs/{FINALIZER_RUN}/attempts/1",
        "completed_at": "2026-10-06T00:06:00Z",
        "output": {"text": json.dumps({"schema": "chio.security-check-authority.v2", "identity": identity,
                    "source_ci": source_ci, "publication_binding_digest": "2" * 64})},
    })
    data[f"{prefix}/commits/{MERGE}/check-runs"] = {"total_count": len(checks), "check_runs": checks}
    data[f"{prefix}/actions/runs/{CI_RUN}/attempts/1/jobs"] = {"total_count": len(jobs), "jobs": jobs}
    finalizer_jobs = [
        {"id": 800 + offset, "name": name, "run_id": FINALIZER_RUN, "head_sha": DEFINITION,
         "status": "completed", "conclusion": "success"}
        for offset, name in enumerate((
            "validate unsigned enterprise Linux capture", "sign committed enterprise Linux migration evidence",
            "authorize dedicated Security contract publication", "reconcile exact merge authority contexts",
        ))
    ]
    data[f"{prefix}/actions/runs/{FINALIZER_RUN}/attempts/1/jobs"] = {"total_count": 4, "jobs": finalizer_jobs}
    for ref in (SOURCE, EVIDENCE, MERGE):
        data[f"{prefix}/contents/.github/workflows/ci.yml?ref={ref}"] = {"sha": "3" * 40}
    for ref in (DEFINITION, PROTECTED):
        data[f"{prefix}/contents/.github/workflows/admin-override-audit.yml?ref={ref}"] = {"sha": "4" * 40}
        data[f"{prefix}/contents/.github/workflows/enterprise-evidence-finalizer.yml?ref={ref}"] = {"sha": "5" * 40}
    script = ROOT / "scripts/audit-security-merge-qualification.py"
    raw = script.read_bytes() if script.exists() else b""
    script_blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    data[f"{prefix}/contents/scripts/audit-security-merge-qualification.py?ref={DEFINITION}"] = {"sha": script_blob}
    for filename in ("ci.yml", "enterprise-evidence-finalizer.yml"):
        record = data[f"{prefix}/actions/workflows/{filename}"]
        data[f"{prefix}/actions/workflows/{record['id']}"] = copy.deepcopy(record)
    data[f"{prefix}/actions/runs"] = data[f"{prefix}/actions/workflows/ci.yml/runs"]
    return data


def retire_current_workflow_registry(data: dict, change: str) -> None:
    prefix = f'repos/{REPOSITORY}/actions/workflows/'
    for key in list(data):
        if not key.startswith(prefix) or key.endswith('/runs'):
            continue
        if change == 'deleted':
            del data[key]
        elif change == 'renamed':
            data[key]['path'] = '.github/workflows/renamed.yml'
        elif change == 'recreated':
            data[key]['id'] = 999


FAKE_GH = r'''#!/usr/bin/env python3
import base64,json,os,sys,urllib.parse,pathlib,subprocess
args=sys.argv[1:]
if args[:2] == ['pr','comment']:
    p=pathlib.Path(os.environ['COMMENT_FILE'])
    with p.open('a') as f: f.write(pathlib.Path(args[args.index('--body-file')+1]).read_text())
    sys.exit(0)
if not args or args[0] != 'api': sys.exit(2)
path=next((a for a in args[1:] if a.startswith('repos/')),None)
data=json.loads(pathlib.Path(os.environ['API_FIXTURE']).read_text())
if path not in data:
    parts=urllib.parse.urlsplit(path)
    query=urllib.parse.parse_qs(parts.query)
    ref=query.get('ref')
    key=parts.path + ('?ref='+ref[0] if ref else '')
    if query.get('page',['1']) != ['1']:
        sys.stderr.write('unexpected missing API page\n');sys.exit(1)
else: key=path
if key not in data:
    sys.stderr.write('unprovided API '+str(path)+'\n');sys.exit(1)
result=data[key]
if isinstance(result,dict) and '__sequence' in result:
    p=pathlib.Path(os.environ['API_FIXTURE']+'.counts')
    counts=json.loads(p.read_text()) if p.exists() else {}
    count=counts.get(key,0);counts[key]=count+1;p.write_text(json.dumps(counts))
    result=result['__sequence'][min(count,len(result['__sequence'])-1)]
if isinstance(result,dict) and '__binary_base64' in result:
    sys.stdout.buffer.write(base64.b64decode(result['__binary_base64']));sys.exit(0)
if '--jq' in args:
    evaluated=subprocess.run(['jq','-c',args[args.index('--jq')+1]],input=json.dumps(result),text=True,capture_output=True,check=False)
    if evaluated.returncode: sys.stderr.write(evaluated.stderr);sys.exit(evaluated.returncode)
    for line in evaluated.stdout.splitlines():
        value=json.loads(line);print(value if isinstance(value,str) else json.dumps(value,separators=(',',':')))
else: print(json.dumps(result))
'''


def run_audit(data: dict[str, dict]) -> tuple[subprocess.CompletedProcess, dict, str]:
    audit = workflow("admin-override-audit.yml")["jobs"]["audit"]
    body = next(step["run"] for step in audit["steps"] if "run" in step)
    with tempfile.TemporaryDirectory(prefix="chio-landing-audit-") as raw:
        directory = Path(raw)
        fixture = directory / "api.json"
        fixture.write_text(json.dumps(data))
        binary = directory / "bin"
        binary.mkdir()
        gh = binary / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        script = ROOT / "scripts/audit-security-merge-qualification.py"
        if script.exists():
            destination = directory / "authorized-auditor/scripts"
            destination.mkdir(parents=True)
            shutil.copy2(script, destination / script.name)
        environment = os.environ | {
            "PATH": str(binary) + os.pathsep + os.environ["PATH"],
            "PYTHONDONTWRITEBYTECODE": "1", "API_FIXTURE": str(fixture),
            "COMMENT_FILE": str(directory / "comment.md"), "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_STEP_SUMMARY": str(directory / "summary.md"), "CHECK_SHA": PROTECTED,
            "PR_NUMBER": str(PR), "SECURITY_APP_ID": str(APP_ID),
            "SECURITY_DEFINITION_SHA": DEFINITION, "AUDIT_WORKFLOW_SHA": PROTECTED,
            "GH_TOKEN": "offline-fixture-token",
        }
        result = subprocess.run(["bash", "-c", body], cwd=directory, env=environment,
                                text=True, capture_output=True, check=False, timeout=30)
        output = directory / "audit.json"
        report = json.loads(output.read_text()) if output.exists() else {}
        comments = directory / "comment.md"
        return result, report, comments.read_text() if comments.exists() else ""


class RecordedQualificationAuditTests(unittest.TestCase):
    def test_historical_audit_accepts_disabled_ci_without_current_activity(self) -> None:
        data = snapshot()
        data[f'repos/{REPOSITORY}/actions/workflows/ci.yml']['state'] = 'disabled_manually'
        result, report, _ = run_audit(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report['status'], 'verified')

    def test_historical_audit_survives_renamed_deleted_recreated_registry(self) -> None:
        for change in ('renamed', 'deleted', 'recreated'):
            with self.subTest(change=change):
                data = snapshot()
                retire_current_workflow_registry(data, change)
                result, report, _ = run_audit(data)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(report['status'], 'verified')

    def test_historical_run_and_recorded_authorizer_identity_substitutions_fail(self) -> None:
        for change in ('ci_workflow_id', 'finalizer_workflow_id', 'ci_path', 'ci_head', 'ci_attempt', 'authorizer_check'):
            with self.subTest(change=change):
                data = snapshot()
                prefix = f'repos/{REPOSITORY}'
                ci = data[f'{prefix}/actions/runs/{CI_RUN}/attempts/1']
                finalizer = data[f'{prefix}/actions/runs/{FINALIZER_RUN}/attempts/1']
                if change == 'ci_workflow_id': ci['workflow_id'] = 999
                elif change == 'finalizer_workflow_id': finalizer['workflow_id'] = 999
                elif change == 'ci_path': ci['path'] = '.github/workflows/untrusted.yml'
                elif change == 'ci_head': ci['head_sha'] = SOURCE
                elif change == 'ci_attempt': ci['run_attempt'] = 2
                else:
                    authority = data[f'{prefix}/commits/{MERGE}/check-runs']['check_runs'][-1]
                    authority['details_url'] = authority['details_url'].replace(f'/runs/{FINALIZER_RUN}/', '/runs/302/')
                result, report, _ = run_audit(data)
                self.assertNotEqual(result.returncode, 0, report)
                self.assertEqual(report['status'], 'unverified')

    def test_main_withdrawal_at_final_boundary_cannot_use_old_reachability(self) -> None:
        data = snapshot()
        prefix = f"repos/{REPOSITORY}"
        old = data[f"{prefix}/git/ref/heads/main"]
        changed = copy.deepcopy(old)
        changed["object"]["sha"] = "1" * 40
        data[f"{prefix}/git/ref/heads/main"] = {"__sequence": [old, changed]}
        data[f"{prefix}/compare/{PROTECTED}...{'1' * 40}"] = {
            "status": "diverged", "behind_by": 1, "merge_base_commit": {"sha": BASE}
        }
        result, report, _ = run_audit(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report.get("status"), "unverified")

    def test_main_forward_descendants_keep_retained_ancestry(self) -> None:
        data = snapshot()
        prefix = f"repos/{REPOSITORY}"
        old = data[f"{prefix}/git/ref/heads/main"]
        changed = copy.deepcopy(old)
        changed["object"]["sha"] = "1" * 40
        data[f"{prefix}/git/ref/heads/main"] = {"__sequence": [old, changed]}
        data[f"{prefix}/compare/{PROTECTED}...{'1' * 40}"] = {
            "status": "ahead", "behind_by": 0, "merge_base_commit": {"sha": PROTECTED}
        }
        result, report, _ = run_audit(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report.get("status"), "verified")
        self.assertEqual(report.get("status"), "verified")

    def test_later_bad_producing_finalizer_attempt_is_sticky(self) -> None:
        for conclusion in ("failure", "cancelled", "timed_out", None):
            with self.subTest(conclusion=conclusion):
                data = snapshot()
                prefix = f"repos/{REPOSITORY}"
                current = data[f"{prefix}/actions/runs/{FINALIZER_RUN}"]
                current["run_attempt"], current["conclusion"] = 2, conclusion
                data[f"{prefix}/actions/runs/{FINALIZER_RUN}/attempts/2"] = copy.deepcopy(current)
                result, report, _ = run_audit(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report.get("status"), "unverified")

    def test_unbound_same_title_finalizer_failure_cannot_withdraw_authority(self) -> None:
        data = snapshot()
        prefix = f"repos/{REPOSITORY}"
        sibling = copy.deepcopy(data[f"{prefix}/actions/runs/{FINALIZER_RUN}"])
        sibling["id"] = 302
        sibling["display_title"] = sibling["display_title"].replace("1" * 64, "3" * 64)
        sibling["conclusion"] = "failure"
        listing = data[f"{prefix}/actions/workflows/enterprise-evidence-finalizer.yml/runs"]
        listing["workflow_runs"].append(sibling)
        listing["total_count"] += 1
        data[f"{prefix}/actions/runs/302"] = sibling
        data[f"{prefix}/actions/runs/302/attempts/1"] = copy.deepcopy(sibling)
        result, report, _ = run_audit(data)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bound_successful_retry_retains_original_authority_without_new_bot_dispatch(self) -> None:
        data = snapshot()
        prefix = f'repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}'
        retry = copy.deepcopy(data[prefix + '/attempts/1'])
        retry.update(run_attempt=2, triggering_actor={'login': 'bb-connor'})
        data[prefix], data[prefix + '/attempts/2'] = retry, copy.deepcopy(retry)
        result, output, _ = run_audit(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output['qualification']['finalizer']['attempts'], [
            {'run_attempt': 1, 'status': 'completed', 'conclusion': 'success'},
            {'run_attempt': 2, 'status': 'completed', 'conclusion': 'success'},
        ])

    def test_current_authorizing_run_source_cannot_change_during_audit(self) -> None:
        data = snapshot()
        data[f'repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}']['head_sha'] = SOURCE
        result, output, _ = run_audit(data)
        self.assertNotEqual(result.returncode, 0, output)

    def test_valid_test_merge_qualification_is_not_reported_as_override(self) -> None:
        result, report, comments = run_audit(snapshot())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(comments, "", "authentic M qualification was falsely reported as override")
        self.assertEqual(report.get("status"), "verified")
        self.assertEqual(report["qualification"]["merge_commit_sha"], MERGE)
        self.assertEqual(report["protected_merge_commit_sha"], PROTECTED)

    def test_ordinary_main_ci_title_cannot_invent_foundation_qualification(self) -> None:
        data = snapshot()
        prefix = f'repos/{REPOSITORY}'
        # Captured PR1176 ordinary CI37472217665 reports name CI and this
        # pull-request title. It carries no authenticated foundation tuple.
        ordinary_title = 'fix(ci): bind authenticated qualification and preserve retry failure history'
        run = data[f'{prefix}/actions/runs/{CI_RUN}']
        run.update(name='CI', display_title=ordinary_title)
        data[f'{prefix}/actions/runs/{CI_RUN}/attempts/1'] = copy.deepcopy(run)
        data[f'{prefix}/actions/workflows/ci.yml/runs']['workflow_runs'] = [run]
        result, report, _ = run_audit(data)
        self.assertNotEqual(result.returncode, 0, report)
        self.assertEqual(report['status'], 'unverified')
        self.assertEqual(report['bypass_attribution'], 'unestablished')

    def test_wrong_app_never_substitutes_for_security_authority(self) -> None:
        data = snapshot()
        data[f"repos/{REPOSITORY}/commits/{MERGE}/check-runs"]["check_runs"][-1]["app"] = {
            "id": 15368, "slug": "github-actions"
        }
        result, report, _ = run_audit(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report.get("status"), "unverified")

    def test_wrong_tree_or_parent_fails_retained_history_audit(self) -> None:
        for field in ("tree", "parents"):
            with self.subTest(field=field):
                data = snapshot()
                commit = data[f"repos/{REPOSITORY}/git/commits/{PROTECTED}"]
                commit[field] = {"sha": "1" * 40} if field == "tree" else [{"sha": BASE}]
                result, report, _ = run_audit(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report.get("status"), "unverified")

    def test_critical_failure_followed_by_success_cannot_pass_audit(self) -> None:
        data = snapshot()
        prefix = f"repos/{REPOSITORY}/actions/runs/{CI_RUN}"
        successful = copy.deepcopy(data[prefix + "/attempts/1"])
        successful["run_attempt"] = 2
        data[prefix + "/attempts/2"] = successful
        data[prefix]["run_attempt"] = 2
        data[prefix + "/attempts/1"]["conclusion"] = "failure"
        result, report, _ = run_audit(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report.get("status"), "unverified")

    def test_every_authority_namespace_requires_authentic_singleton_success(self) -> None:
        def corrupt_metadata(check):
            metadata = json.loads(check["output"]["text"])
            metadata["identity"]["authorized_source_sha"] = "1" * 40
            check["output"]["text"] = json.dumps(metadata)

        for label in ("wrong-external-id", "wrong-slug", "failure", "neutral", "null",
                      "late", "duplicate", "wrong-metadata", "invalid-json"):
            with self.subTest(mutation=label):
                data = snapshot()
                namespace = data[f"repos/{REPOSITORY}/commits/{MERGE}/check-runs"]
                check = namespace["check_runs"][-1]
                if label == "wrong-external-id":
                    check["external_id"] = check["external_id"].replace(SOURCE, "1" * 40)
                elif label == "wrong-slug":
                    check["app"]["slug"] = "other-authority"
                elif label in ("failure", "neutral", "null"):
                    check["conclusion"] = None if label == "null" else label
                elif label == "late":
                    check["completed_at"] = "2026-10-06T00:11:00Z"
                elif label == "duplicate":
                    duplicate = copy.deepcopy(namespace["check_runs"][0])
                    duplicate["id"] = 999
                    namespace["check_runs"].append(duplicate)
                    namespace["total_count"] += 1
                elif label == "wrong-metadata":
                    corrupt_metadata(check)
                else:
                    check["output"]["text"] = "{invalid"
                result, report, _ = run_audit(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report.get("status"), "unverified")

    def test_other_ci_or_finalizer_attempt_is_not_substituted(self) -> None:
        for label in ("source-job", "source-check", "finalizer-attempt", "failed-finalizer", "source-ci"):
            with self.subTest(mutation=label):
                data = snapshot()
                prefix = f"repos/{REPOSITORY}"
                if label == "source-job":
                    data[f"{prefix}/actions/runs/{CI_RUN}/attempts/1/jobs"]["jobs"][0]["head_sha"] = SOURCE
                elif label == "source-check":
                    data[f"{prefix}/check-runs/501"]["check_suite"]["id"] = 999
                elif label == "finalizer-attempt":
                    data[f"{prefix}/actions/runs/{FINALIZER_RUN}/attempts/1"]["run_attempt"] = 2
                elif label == "failed-finalizer":
                    data[f"{prefix}/actions/runs/{FINALIZER_RUN}/attempts/1/jobs"]["jobs"][-1]["conclusion"] = "failure"
                else:
                    check = data[f"{prefix}/commits/{MERGE}/check-runs"]["check_runs"][0]
                    metadata = json.loads(check["output"]["text"])
                    metadata["source_ci"]["run_id"] = "202"
                    check["output"]["text"] = json.dumps(metadata)
                result, report, _ = run_audit(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report.get("status"), "unverified")

    def test_incomplete_or_untrusted_source_proof_fails_closed(self) -> None:
        for label in ("missing-page", "ci-definition", "auditor-definition", "auditor-source", "source-ancestry", "main-ancestry"):
            with self.subTest(mutation=label):
                data = snapshot()
                prefix = f"repos/{REPOSITORY}"
                if label == "missing-page":
                    data[f"{prefix}/commits/{MERGE}/check-runs"]["total_count"] += 1
                elif label == "ci-definition":
                    data[f"{prefix}/contents/.github/workflows/ci.yml?ref={EVIDENCE}"]["sha"] = "0" * 40
                elif label == "auditor-definition":
                    data[f"{prefix}/contents/.github/workflows/admin-override-audit.yml?ref={PROTECTED}"]["sha"] = "0" * 40
                elif label == "auditor-source":
                    data[f"{prefix}/contents/scripts/audit-security-merge-qualification.py?ref={DEFINITION}"]["sha"] = "0" * 40
                elif label == "source-ancestry":
                    data[f"{prefix}/compare/{SOURCE}...{EVIDENCE}"]["merge_base_commit"]["sha"] = "0" * 40
                else:
                    data[f"{prefix}/compare/{PROTECTED}...{PROTECTED}"]["merge_base_commit"]["sha"] = "0" * 40
                result, report, _ = run_audit(data)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(report.get("status"), "unverified")

    def test_repository_ids_are_not_replaced_by_reused_names(self) -> None:
        data = snapshot()
        data[f"repos/{REPOSITORY}/pulls/{PR}"]["head"]["repo"]["id"] = 999
        result, report, _ = run_audit(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report.get("status"), "unverified")

    def test_missing_check_suite_ids_cannot_authenticate_mirrors(self) -> None:
        data = snapshot()
        prefix = f"repos/{REPOSITORY}"
        for path in (f"actions/runs/{CI_RUN}", f"actions/runs/{CI_RUN}/attempts/1"):
            data[f"{prefix}/{path}"]["check_suite_id"] = None
        for identifier in range(501, 505):
            data[f"{prefix}/check-runs/{identifier}"]["check_suite"]["id"] = None
        result, report, _ = run_audit(data)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(report.get("status"), "unverified")


class SeccompOriginalRedTests(unittest.TestCase):
    @staticmethod
    def decision(profile: dict, name: str, arguments: tuple[int, ...] = ()) -> tuple[str, int]:
        matches = []
        for rule in profile["syscalls"]:
            if name not in rule["names"] or rule.get("includes", {}).get("caps"):
                continue
            include_arches = rule.get("includes", {}).get("arches", [])
            exclude_arches = rule.get("excludes", {}).get("arches", [])
            if include_arches and "amd64" not in include_arches or "amd64" in exclude_arches:
                continue
            satisfied = True
            for argument in rule.get("args", []):
                actual = arguments[argument["index"]] if argument["index"] < len(arguments) else 0
                value = argument["value"]
                operation = argument["op"]
                comparisons = {
                    "SCMP_CMP_EQ": actual == value, "SCMP_CMP_NE": actual != value,
                    "SCMP_CMP_LT": actual < value, "SCMP_CMP_LE": actual <= value,
                    "SCMP_CMP_GT": actual > value, "SCMP_CMP_GE": actual >= value,
                    "SCMP_CMP_MASKED_EQ": actual & value == argument.get("valueTwo", 0),
                }
                if operation not in comparisons:
                    raise AssertionError("unhandled seccomp argument comparison")
                satisfied &= comparisons[operation]
            if satisfied:
                matches.append((rule["action"], rule.get("errnoRet", profile["defaultErrnoRet"])))
        denied = [match for match in matches if match[0] == "SCMP_ACT_ERRNO"]
        if denied:
            return denied[0]
        return matches[0] if matches else (profile["defaultAction"], profile["defaultErrnoRet"])

    @staticmethod
    def profile() -> dict:
        return json.loads((ROOT / "deploy/docker/security-evidence-seccomp.json").read_text())

    def test_unlisted_candidate_syscall_is_denied_by_default(self) -> None:
        profile = json.loads((ROOT / "deploy/docker/security-evidence-seccomp.json").read_text())
        self.assertEqual(profile["defaultAction"], "SCMP_ACT_ERRNO")

    def test_io_uring_is_not_permitted_by_an_unnamed_default_rule(self) -> None:
        profile = json.loads((ROOT / "deploy/docker/security-evidence-seccomp.json").read_text())
        for name in ("io_uring_setup", "io_uring_enter", "io_uring_register"):
            actions = [rule["action"] for rule in profile["syscalls"] if name in rule["names"]]
            self.assertNotIn("SCMP_ACT_ALLOW", actions)
            self.assertTrue(actions or profile["defaultAction"] == "SCMP_ACT_ERRNO", name)

    def test_capture_grants_only_the_designated_x64_abi(self) -> None:
        self.assertEqual(self.profile().get("architectures"), ["SCMP_ARCH_X86_64"])

    def test_clone3_deny_keeps_the_standard_thread_fallback_errno(self) -> None:
        self.assertEqual(self.decision(self.profile(), "clone3"), ("SCMP_ACT_ERRNO", 38))

    def test_personality_and_kernel_crypto_socket_arguments_stay_restricted(self) -> None:
        profile = self.profile()
        self.assertEqual(self.decision(profile, "personality", (0x0040000,))[0], "SCMP_ACT_ERRNO")
        self.assertEqual(self.decision(profile, "socket", (38, 5, 0))[0], "SCMP_ACT_ERRNO")

    def test_supervisor_helpers_and_namespace_denial_keep_their_roles(self) -> None:
        profile = self.profile()
        for name, arguments in (("read", ()), ("write", ()), ("execve", ()),
                                ("futex", ()), ("socket", (1, 1, 0)),
                                ("personality", (0,)), ("clone", (17,))):
            with self.subTest(helper=name):
                self.assertEqual(self.decision(profile, name, arguments)[0], "SCMP_ACT_ALLOW")
        for mask in (128, 131072, 33554432, 67108864, 134217728, 268435456, 536870912, 1073741824):
            with self.subTest(namespace_flag=mask):
                self.assertEqual(self.decision(profile, "clone", (mask | 17,))[0], "SCMP_ACT_ERRNO")
        for name in ("mount", "setns", "unshare", "process_vm_readv", "process_vm_writev", "bpf", "io_uring_setup"):
            with self.subTest(forbidden=name):
                self.assertEqual(self.decision(profile, name)[0], "SCMP_ACT_ERRNO")


class DocumentLandingContractTests(unittest.TestCase):
    def reject(self, mutate) -> None:
        document = (ROOT / "docs/security/committed-linux-evidence.md").read_text()
        with tempfile.TemporaryDirectory(prefix="chio-landing-policy-") as raw:
            fixture = Path(raw)
            destination = fixture / "docs/security/committed-linux-evidence.md"
            destination.parent.mkdir(parents=True)
            destination.write_text(mutate(document))
            with self.assertRaises(CHECKER.ContractError):
                CHECKER.validate_environment_provisioning_document(fixture)

    def test_linear_history_cannot_block_the_required_retained_merge(self) -> None:
        self.reject(lambda text: text.replace(
            '    {type: "deletion"},',
            '    {type: "deletion"},\n    {type: "required_linear_history"},', 1,
        ))

    def test_only_squash_rebase_cannot_rewrite_required_evidence_identity(self) -> None:
        self.reject(lambda text: re.sub(
            r'allowed_merge_methods: \[[^\]]+\]',
            'allowed_merge_methods: ["squash", "rebase"]', text, count=1,
        ))


class RunIdentityLivenessTests(unittest.TestCase):
    def test_bad_retry_keeps_immutable_first_attempt_as_authority_anchor(self) -> None:
        body = next(step["run"] for step in workflow("security-contract-revocation.yml")["jobs"]["bind-revocation"]["steps"]
                    if step.get("name") == "Bind failed finalizer to existing authority")
        start = body.index('          upstream="$(gh api') if '          upstream="$(gh api' in body else body.index('upstream="$(gh api')
        end = body.index('finalizer_jobs="$({', start)
        fragment = body[start:end]
        data = snapshot()
        failed = copy.deepcopy(data[f"repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}/attempts/1"])
        failed["run_attempt"], failed["conclusion"] = 2, "failure"
        failed["triggering_actor"] = {"login": "bb-connor"}
        data[f"repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}/attempts/2"] = failed
        with tempfile.TemporaryDirectory(prefix="chio-finalizer-anchor-") as raw:
            root = Path(raw)
            fixture = root / "api.json"
            fixture.write_text(json.dumps(data))
            gh = root / "gh"
            gh.write_text(FAKE_GH)
            gh.chmod(0o755)
            result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + fragment + '\ntest "${run_attempt}" = 1'],
                                    capture_output=True, text=True, check=False,
                                    env=os.environ | {"PATH": str(root) + os.pathsep + os.environ["PATH"],
                                                      "API_FIXTURE": str(fixture), "GITHUB_REPOSITORY": REPOSITORY,
                                                      "EVENT_RUN_ID": str(FINALIZER_RUN), "EVENT_WORKFLOW_ID": str(FINALIZER_WORKFLOW),
                                                      "EVENT_RUN_ATTEMPT": "2", "EVENT_CONCLUSION": "failure", "REPOSITORY_ID": "1195888645"})
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_disabled_other_producer_does_not_suppress_critical_route(self) -> None:
        route = next(step for step in workflow("security-contract-revocation.yml")["jobs"]["bind-revocation"]["steps"]
                     if step.get("id") == "route")["run"]
        for event_id, unrelated, expected_path in (
            (CI_WORKFLOW, "enterprise-evidence-finalizer.yml", ".github/workflows/ci.yml"),
            (FINALIZER_WORKFLOW, "ci.yml", ".github/workflows/enterprise-evidence-finalizer.yml"),
        ):
            with self.subTest(event_id=event_id):
                data = snapshot()
                data[f"repos/{REPOSITORY}/actions/workflows/{unrelated}"]["state"] = "disabled_manually"
                event_run = CI_RUN if event_id == CI_WORKFLOW else FINALIZER_RUN
                event_record = data[f"repos/{REPOSITORY}/actions/runs/{event_run}/attempts/1"]
                event_record['conclusion'] = 'failure'

                with tempfile.TemporaryDirectory(prefix="chio-route-") as raw:
                    root = Path(raw)
                    fixture = root / "api.json"
                    fixture.write_text(json.dumps(data))
                    gh = root / "gh"
                    gh.write_text(FAKE_GH)
                    gh.chmod(0o755)
                    output = root / "output"
                    result = subprocess.run(["bash", "-c", route], capture_output=True, text=True, check=False,
                                            env=os.environ | {"PATH": str(root) + os.pathsep + os.environ["PATH"],
                                                              "API_FIXTURE": str(fixture), "GITHUB_OUTPUT": str(output),
                                                              "GITHUB_REPOSITORY": REPOSITORY, "EVENT_WORKFLOW_ID": str(event_id), "EVENT_RUN_ID": str(event_run), "EVENT_RUN_ATTEMPT": "1", "EVENT_CONCLUSION": "failure", "REPOSITORY_ID": "1195888645"})
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(output.read_text(), f"workflow_path={expected_path}\n")

    def filter(self, workflow_name: str, job_id: str, marker: str) -> str:
        body = "\n".join(step.get("run", "") for step in workflow(workflow_name)["jobs"][job_id]["steps"])
        predicates = [match.group(1) for match in re.finditer(r"'([^']*)'", body)
                      if match.group(1).startswith("[.[] | select(") and marker in match.group(1)]
        self.assertEqual(len(predicates), 1, "the real workflow discovery predicate must be unique")
        return predicates[0]

    def check_ci_filter(self, job_id: str) -> None:
        predicate = self.filter("enterprise-evidence-finalizer.yml", job_id,
                                '.path == ".github/workflows/ci.yml"')
        run = snapshot()[f"repos/{REPOSITORY}/actions/runs/{CI_RUN}"]
        run["name"] = run["display_title"]
        run["head_branch"] = "integration/process-security-m4"
        command = ["jq", "-c", "--arg", "evidence_sha", EVIDENCE,
                   "--arg", "expected_run_name", run["display_title"],
                   "--arg", "head_ref", run["head_branch"], "--arg", "repository", REPOSITORY,
                   "--arg", "workflow_id", str(CI_WORKFLOW), predicate]
        result = subprocess.run(command, input=json.dumps([run]), capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([item["id"] for item in json.loads(result.stdout)], [CI_RUN])

    def test_ci_publication_discovers_the_actual_dynamic_run_name(self) -> None:
        self.check_ci_filter("authorize-security-check-publication")

    def test_late_failure_history_discovers_the_actual_dynamic_run_name(self) -> None:
        self.check_ci_filter("publish-security-contract")

    def test_finalizer_dispatch_matches_id_path_and_nonce_title(self) -> None:
        predicate = self.filter("enterprise-linux-capture.yml", "dispatch-trusted-finalizer",
                                '.path == ".github/workflows/enterprise-evidence-finalizer.yml"')
        run = snapshot()[f"repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}/attempts/1"]
        run["name"], run["status"] = run["display_title"], "in_progress"
        command = ["jq", "-c", "--arg", "actor", "github-actions[bot]",
                   "--arg", "display_title", run["display_title"], "--arg", "head_branch", "main",
                   "--arg", "head_sha", DEFINITION, "--arg", "started_at", "2026-10-06T00:00:00Z",
                   "--arg", "workflow_id", str(FINALIZER_WORKFLOW), predicate]
        result = subprocess.run(command, input=json.dumps([run]), capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([item["id"] for item in json.loads(result.stdout)], [FINALIZER_RUN])

    def test_finalizer_job_metadata_uses_the_authenticated_run_title(self) -> None:
        step = next(step for step in workflow("security-contract-revocation.yml")["jobs"]["bind-revocation"]["steps"]
                    if step.get("name") == "Bind failed finalizer to existing authority")
        checks = [line.strip() for line in step["run"].splitlines()
                  if "test " in line and "'.workflow_name'" in line]
        self.assertEqual(len(checks), 2)
        upstream = snapshot()[f"repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}/attempts/1"]
        job = {"workflow_name": upstream["display_title"]}
        result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + "\n".join(checks)],
                                env=os.environ | {"upstream": json.dumps(upstream), "finalizer_job": json.dumps(job),
                                                  "publisher_job": json.dumps(job)},
                                text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)


class PlatformShapedFinalizerBinderTests(unittest.TestCase):
    def bind(self, mutation: str = '', conclusion: str | None = 'failure', workflow_state: str = 'active', registry_change: str = '') -> tuple[subprocess.CompletedProcess, str]:
        body = next(step['run'] for step in workflow('security-contract-revocation.yml')['jobs']['bind-revocation']['steps']
                    if step.get('name') == 'Bind failed finalizer to existing authority')
        data = snapshot()
        prefix = f'repos/{REPOSITORY}'
        data[f'{prefix}/actions/workflows/enterprise-evidence-finalizer.yml']['state'] = workflow_state
        original = copy.deepcopy(data[f'{prefix}/actions/runs/{FINALIZER_RUN}/attempts/1'])
        retry = copy.deepcopy(original)
        retry.update(run_attempt=2, conclusion=conclusion, triggering_actor={'login': 'bb-connor'})
        data[f'{prefix}/actions/runs/{FINALIZER_RUN}/attempts/2'] = retry
        data[f'{prefix}/actions/workflows/security-contract-revocation.yml'] = {'id': 103, 'path': '.github/workflows/security-contract-revocation.yml', 'state': 'active'}
        data[f'{prefix}/actions/runs/901'] = {'id': 901, 'workflow_id': 103, 'path': '.github/workflows/security-contract-revocation.yml',
                                             'event': 'workflow_run', 'status': 'in_progress', 'conclusion': None,
                                             'head_sha': DEFINITION, 'head_branch': 'main', 'run_attempt': 1}
        data[f'{prefix}/contents/.github/workflows/security-contract-revocation.yml?ref={DEFINITION}'] = {'sha': '4' * 40}
        jobs = data[f'{prefix}/actions/runs/{FINALIZER_RUN}/attempts/1/jobs']['jobs']
        # API 2026-03-10 observations for CI37366976682 and standalone
        # dispatch37448107390 return the dynamic title in workflow_name.
        for job in jobs:
            job.update(workflow_name=original['display_title'], started_at='2026-10-06T00:00:00Z', completed_at='2026-10-06T00:04:00Z')
        intent = {'schema': 'chio.enterprise-finalizer-dispatch-intent.v1', 'repository': REPOSITORY,
                  'authorized_source_sha': SOURCE, 'capture_run_attempt': '1', 'capture_run_id': '401',
                  'default_commit_sha': DEFINITION, 'dispatch_job_key': 'dispatch-trusted-finalizer',
                  'dispatch_nonce': '1' * 64, 'finalizer_run_attempt': '1', 'finalizer_run_id': str(FINALIZER_RUN),
                  'merge_commit_sha': MERGE, 'pr_number': str(PR), 'source_sha': EVIDENCE, 'security_definition_sha': DEFINITION}
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, 'w') as archive:
            info = zipfile.ZipInfo('finalizer-dispatch-intent.json')
            info.external_attr, info.compress_type = 0o100600 << 16, zipfile.ZIP_DEFLATED
            archive.writestr(info, json.dumps(intent, sort_keys=True, separators=(',', ':')).encode() + b'\n')
        content = buffer.getvalue()
        artifact = {'id': 911, 'name': f'authenticated-finalizer-intent-{FINALIZER_RUN}-1',
                    'size_in_bytes': len(content), 'digest': 'sha256:' + hashlib.sha256(content).hexdigest(),
                    'expired': False, 'workflow_run': {'id': FINALIZER_RUN},
                    'created_at': '2026-10-06T00:00:05Z', 'updated_at': '2026-10-06T00:00:10Z'}
        data[f'{prefix}/actions/runs/{FINALIZER_RUN}/artifacts'] = {'total_count': 1, 'artifacts': [artifact]}
        data[f'{prefix}/actions/artifacts/911/zip'] = {'__binary_base64': base64.b64encode(content).decode()}
        if mutation == 'workflow_id': retry['workflow_id'] = 999
        elif mutation == 'workflow_path': retry['path'] = '.github/workflows/untrusted.yml'
        elif mutation == 'run_head': retry['head_sha'] = SOURCE
        elif mutation == 'job_run': jobs[0]['run_id'] = 999
        elif mutation == 'job_head': jobs[0]['head_sha'] = SOURCE
        elif mutation == 'static_job_label': jobs[0]['workflow_name'] = 'Enterprise evidence finalizer'
        elif mutation == 'publisher_static_label': jobs[-1]['workflow_name'] = 'Enterprise evidence finalizer'
        data[f'{prefix}/actions/runs/901']['repository'] = {'full_name': REPOSITORY, 'id': 42}
        data[f'{prefix}/actions/runs/901']['head_repository'] = {'full_name': REPOSITORY, 'id': 42}
        data[f'{prefix}/actions/runs/901/attempts/1'] = data[f'{prefix}/actions/runs/901']
        if registry_change: retire_current_workflow_registry(data, registry_change)
        with tempfile.TemporaryDirectory(prefix='chio-platform-shaped-binder-') as raw:
            root = Path(raw)
            fixture = root / 'api.json'
            fixture.write_text(json.dumps(data))
            gh = root / 'gh'
            gh.write_text(FAKE_GH)
            gh.chmod(0o755)
            output = root / 'output'
            env = os.environ | {'PATH': str(root) + os.pathsep + os.environ['PATH'], 'API_FIXTURE': str(fixture),
                                'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REPOSITORY_OWNER': 'bb-connor',
                                'GITHUB_OUTPUT': str(output), 'RUNNER_TEMP': str(root), 'DEFAULT_BRANCH': 'main',
                                'EVENT_ACTION': 'completed', 'EVENT_CONCLUSION': conclusion or '', 'EVENT_RUN_ATTEMPT': '2',
                                'EVENT_RUN_ID': str(FINALIZER_RUN), 'EVENT_WORKFLOW_ID': str(FINALIZER_WORKFLOW),
                                'LISTENER_REF': 'refs/heads/main', 'LISTENER_RUN_ATTEMPT': '1', 'LISTENER_RUN_ID': '901',
                                'LISTENER_SHA': DEFINITION, 'SECURITY_APP_ID': str(APP_ID), 'SECURITY_DEFINITION_SHA': DEFINITION,
                                'REPOSITORY_ID': '1195888645',
                                'GH_TOKEN': 'offline-fixture-only'}
            result = subprocess.run(['bash', '-c', body], env=env, capture_output=True, text=True, check=False, timeout=30)
            self.assertEqual(fixture.read_text(), json.dumps(data), 'binder unexpectedly mutated the API fixture')
            return result, output.read_text() if output.exists() else ''

    def test_platform_dynamic_job_title_authenticates_full_failed_retry_binder(self) -> None:
        for conclusion in ('failure', 'cancelled', 'timed_out', None):
            with self.subTest(conclusion=conclusion):
                result, output = self.bind(conclusion=conclusion)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('eligible=true', output)
                self.assertIn('create_missing=false', output)

    def test_platform_job_and_workflow_identity_substitutions_are_rejected(self) -> None:
        for mutation in ('workflow_id', 'workflow_path', 'run_head', 'job_run', 'job_head', 'static_job_label', 'publisher_static_label'):
            with self.subTest(mutation=mutation):
                result, output = self.bind(mutation=mutation)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertNotIn('eligible=true', output)

    def test_disabled_finalizer_retains_historical_failure_authentication(self) -> None:
        for state in ('disabled_manually', 'disabled_inactivity', 'disabled_fork'):
            with self.subTest(state=state):
                result, output = self.bind(workflow_state=state)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('eligible=true', output)
                self.assertIn('create_missing=false', output)

    def test_finalizer_historical_binding_survives_registry_replacement(self) -> None:
        for change in ('renamed', 'deleted', 'recreated'):
            with self.subTest(change=change):
                result, output = self.bind(registry_change=change)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('eligible=true', output)
                self.assertIn('create_missing=false', output)


class DisabledCriticalCiBinderTests(unittest.TestCase):
    def test_disabled_ci_still_binds_exact_bad_attempt_to_existing_authority(self) -> None:
        body = next(step['run'] for step in workflow('security-contract-revocation.yml')['jobs']['bind-revocation']['steps']
                    if step.get('name') == 'Bind later failed CI rerun to existing authority')
        for state, registry_change in (('active',''), ('disabled_manually',''), ('disabled_inactivity',''), ('disabled_fork',''), ('active','renamed'), ('active','deleted'), ('active','recreated')):
            with self.subTest(state=state, registry_change=registry_change):
                data = snapshot()
                prefix = f'repos/{REPOSITORY}'
                data[f'{prefix}/actions/workflows/ci.yml']['state'] = state
                bad = copy.deepcopy(data[f'{prefix}/actions/runs/{CI_RUN}/attempts/1'])
                bad.update(run_attempt=2, conclusion='failure')
                data[f'{prefix}/actions/runs/{CI_RUN}/attempts/2'] = bad
                data[f'{prefix}/actions/runs/{CI_RUN}/attempts/2/jobs'] = {'total_count': 1, 'jobs': [
                    {'id': 901, 'name': 'attest exact pull request merge binding', 'run_id': CI_RUN,
                     'head_sha': EVIDENCE, 'status': 'completed', 'conclusion': 'failure'}]}
                data[f'{prefix}/actions/runs/{CI_RUN}/artifacts'] = {'total_count': 0, 'artifacts': []}
                data[f'{prefix}/actions/workflows/security-contract-revocation.yml'] = {'id': 103, 'path': '.github/workflows/security-contract-revocation.yml', 'state': 'active'}
                data[f'{prefix}/actions/runs/901'] = {'id': 901, 'workflow_id': 103, 'path': '.github/workflows/security-contract-revocation.yml',
                                                     'event': 'workflow_run', 'status': 'in_progress', 'head_sha': DEFINITION,
                                                     'head_branch': 'main', 'run_attempt': 1}
                data[f'{prefix}/contents/.github/workflows/security-contract-revocation.yml?ref={DEFINITION}'] = {'sha': '4' * 40}
                data[f'{prefix}/actions/runs/901']['repository'] = {'full_name': REPOSITORY, 'id': 42}
                data[f'{prefix}/actions/runs/901']['head_repository'] = {'full_name': REPOSITORY, 'id': 42}
                data[f'{prefix}/actions/runs/901/attempts/1'] = data[f'{prefix}/actions/runs/901']
                if registry_change: retire_current_workflow_registry(data, registry_change)
                with tempfile.TemporaryDirectory(prefix='chio-disabled-ci-binder-') as raw:
                    root = Path(raw)
                    fixture = root / 'api.json'
                    fixture.write_text(json.dumps(data))
                    gh = root / 'gh'
                    gh.write_text(FAKE_GH)
                    gh.chmod(0o755)
                    output = root / 'output'
                    env = os.environ | {'PATH': str(root) + os.pathsep + os.environ['PATH'], 'API_FIXTURE': str(fixture),
                                        'GITHUB_REPOSITORY': REPOSITORY, 'GITHUB_REPOSITORY_OWNER': 'bb-connor',
                                        'GITHUB_OUTPUT': str(output), 'RUNNER_TEMP': str(root), 'DEFAULT_BRANCH': 'main',
                                        'EVENT_ACTION': 'completed', 'EVENT_CONCLUSION': 'failure', 'EVENT_RUN_ATTEMPT': '2',
                                        'EVENT_RUN_ID': str(CI_RUN), 'EVENT_WORKFLOW_ID': str(CI_WORKFLOW),
                                        'LISTENER_REF': 'refs/heads/main', 'LISTENER_RUN_ATTEMPT': '1', 'LISTENER_RUN_ID': '901',
                                        'LISTENER_SHA': DEFINITION, 'SECURITY_APP_ID': str(APP_ID), 'SECURITY_DEFINITION_SHA': DEFINITION,
                                        'AUTHORIZED_SOURCE_SHA': SOURCE, 'COMMITTED_EVIDENCE_SHA': EVIDENCE,
                                        'REPOSITORY_ID': '1195888645', 'REPOSITORY_OWNER_ID': '1', 'GH_TOKEN': 'offline-fixture-only'}
                    result = subprocess.run(['bash', '-c', body], env=env, capture_output=True, text=True, check=False, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertIn('eligible=true', output.read_text() if output.exists() else '')
                    self.assertIn('create_missing=false', output.read_text() if output.exists() else '')
                    self.assertEqual(fixture.read_text(), json.dumps(data), 'binder wrote authority while authenticating a historical failure')


FAKE_CURL = r'''#!/usr/bin/env python3
import json,os,sys,pathlib,urllib.parse
args=sys.argv[1:]
url=next(a for a in args if a.startswith('https://api.github.com/'))
parts=urllib.parse.urlsplit(url)
key=parts.path.lstrip('/')
query=urllib.parse.parse_qs(parts.query)
if 'ref' in query: key += '?ref='+query['ref'][0]
p=pathlib.Path(os.environ['API_FIXTURE']);data=json.loads(p.read_text())
method=args[args.index('--request')+1] if '--request' in args else 'GET'
if method=='PATCH':
    payload=json.loads(args[args.index('--data-binary')+1]);check_id=int(key.rsplit('/',1)[1])
    checks=data['repos/'+os.environ['GITHUB_REPOSITORY']+'/commits/'+os.environ['MERGE_COMMIT_SHA']+'/check-runs']['check_runs']
    result=next(c for c in checks if c['id']==check_id);result.update(payload)
    p.write_text(json.dumps(data))
elif method!='GET':
    sys.stderr.write('unexpected mutation '+method+'\n');sys.exit(1)
else:
    if key not in data: sys.stderr.write('unprovided API '+key+'\n');sys.exit(1)
    result=data[key]
    if 'check_name' in query:
        checks=[c for c in result['check_runs'] if c['name']==query['check_name'][0] and str(c['app']['id'])==query['app_id'][0]]
        result={'total_count':len(checks),'check_runs':checks}
print(json.dumps(result))
'''


class AuthorizingFinalizerRetryTests(unittest.TestCase):
    def test_recorded_authorizer_reconciliation_survives_retired_registry(self) -> None:
        for change in ('renamed', 'deleted', 'recreated'):
            with self.subTest(change=change):
                data = snapshot()
                retire_current_workflow_registry(data, change)
                result, observed = self.run_publisher_guard(data)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(observed, data)

    def run_listener_binding(self, data: dict) -> tuple[subprocess.CompletedProcess, str]:
        body = next(step['run'] for step in workflow('security-contract-revocation.yml')['jobs']['bind-revocation']['steps']
                    if step.get('name') == 'Bind failed finalizer to existing authority')
        fragment = body[body.index('relevant_count="', body.index('finalizer_details_url=')):]
        with tempfile.TemporaryDirectory(prefix='chio-finalizer-recorded-binding-') as raw:
            root = Path(raw)
            fixture = root / 'api.json'
            fixture.write_text(json.dumps(data))
            gh = root / 'gh'
            gh.write_text(FAKE_GH)
            gh.chmod(0o755)
            output = root / 'output'
            checks = data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs']
            result = subprocess.run(['bash', '-c', 'set -euo pipefail\n' + fragment], capture_output=True, text=True, check=False,
                                    env=os.environ | {'PATH': str(root) + os.pathsep + os.environ['PATH'],
                                                      'API_FIXTURE': str(fixture), 'GITHUB_REPOSITORY': REPOSITORY,
                                                      'GITHUB_OUTPUT': str(output), 'SECURITY_APP_ID': str(APP_ID),
                                                      'SECURITY_DEFINITION_SHA': DEFINITION, 'historical_security_definition_sha': DEFINITION,
                                                      'upstream_sha': DEFINITION, 'EVENT_RUN_ID': str(FINALIZER_RUN),
                                                      'failed_finalizer_attempt': '2', 'run_attempt': '1',
                                                      'existing_checks': json.dumps(checks), 'external_id': EXTERNAL_ID,
                                                      'finalizer_details_url': f'https://github.com/{REPOSITORY}/actions/runs/{FINALIZER_RUN}/attempts/1',
                                                      'authorized_source_sha': SOURCE, 'evidence_sha': EVIDENCE,
                                                      'merge_commit_sha': MERGE, 'base_sha': BASE, 'merge_tree_sha': TREE,
                                                      'pr_number': str(PR)})
            return result, output.read_text() if output.exists() else ''

    def test_listener_retry_rejects_substituted_recorded_source_ci(self) -> None:
        data = snapshot()
        authority = data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs'][-1]
        text = json.loads(authority['output']['text'])
        text['source_ci']['run_id'] = '999'
        authority['output']['text'] = json.dumps(text)
        result, output = self.run_listener_binding(data)
        self.assertTrue(result.returncode != 0 or 'eligible=false' in output, result.stdout + output)

    def test_listener_retry_rejects_wrong_app_slug_and_head(self) -> None:
        for mutation in ('app_slug', 'head'):
            with self.subTest(mutation=mutation):
                data = snapshot()
                authority = data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs'][-1]
                if mutation == 'app_slug': authority['app']['slug'] = 'untrusted-app'
                else: authority['head_sha'] = EVIDENCE
                result, output = self.run_listener_binding(data)
                self.assertTrue(result.returncode != 0 or 'eligible=false' in output, result.stdout + output)

    def test_listener_retry_authenticates_existing_recorded_source_ci(self) -> None:
        result, output = self.run_listener_binding(snapshot())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('eligible=true', output)
        self.assertIn('create_missing=false', output)

    def test_listener_unbound_sibling_cannot_invent_existing_app_anchor(self) -> None:
        data = snapshot()
        authority = data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs'][-1]
        authority['details_url'] = f'https://github.com/{REPOSITORY}/actions/runs/302/attempts/1'
        result, output = self.run_listener_binding(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output, 'eligible=false\n')

    def run_publisher_guard(self, data: dict, own_run: int = 901, own_attempt: int = 1,
                            full_publication: bool = False) -> tuple[subprocess.CompletedProcess, dict]:
        body = next(step['run'] for step in workflow('enterprise-evidence-finalizer.yml')['jobs']['publish-security-contract']['steps']
                    if step.get('name') == 'Reconcile exact five-context merge authority')
        namespace = body[body.index('list_namespace_checks() {'):body.index('normalize_bad_ci_namespace() {')]
        start = body.find('reconcile_bad_authorizing_finalizer() {')
        helper = body[start:body.index('require_publishable_ci() {', start)] if start >= 0 else ''
        guard = body[body.index('require_publishable_ci() {'):body.index('publish_success_authority() {')]
        success = body[body.index('publish_success_authority() {'):body.index('\nreconcile_bad_ci\nif test "${bad_ci_observed}"')]
        mirrors = body[body.index('list_actions_mirror_checks() {'):body.index('list_namespace_checks() {')]
        with tempfile.TemporaryDirectory(prefix='chio-finalizer-negative-scan-') as raw:
            root = Path(raw)
            fixture = root / 'api.json'
            fixture.write_text(json.dumps(data))
            curl = root / 'curl'
            curl.write_text(FAKE_CURL)
            curl.chmod(0o755)
            result = subprocess.run(['bash', '-c', 'set -euo pipefail\nshopt -s inherit_errexit\n'
                                     + namespace + helper + '\nreconcile_bad_ci() { bad_ci_observed=false; }\n'
                                     + '\nrevalidate_live_publication_head() { return 0; }\n' + guard
                                     + (mirrors + success + '\npublish_success_authority\n' if full_publication else '\nrequire_publishable_ci\necho success-publication-allowed\n')],
                                    capture_output=True, text=True, check=False,
                                    env=os.environ | {'PATH': str(root) + os.pathsep + os.environ['PATH'],
                                                      'API_FIXTURE': str(fixture), 'GITHUB_REPOSITORY': REPOSITORY,
                                                      'AUTHORIZED_SOURCE_SHA': SOURCE, 'EVIDENCE_SHA': EVIDENCE,
                                                      'MERGE_COMMIT_SHA': MERGE, 'PR_NUMBER': str(PR),
                                                      'SECURITY_APP_ID': str(APP_ID), 'SECURITY_DEFINITION_SHA': DEFINITION,
                                                      'CI_RUN_ID': str(CI_RUN), 'CI_RUN_ATTEMPT': '1', 'CI_WORKFLOW_ID': str(CI_WORKFLOW),
                                                      'FINALIZER_RUN_ID': str(own_run), 'FINALIZER_RUN_ATTEMPT': str(own_attempt),
                                                      'PUBLICATION_BINDING_DIGEST': '2' * 64,
                                                      'publication_details_url': f'https://github.com/{REPOSITORY}/actions/runs/{own_run}/attempts/{own_attempt}',
                                                      'canonical_binding': json.dumps({'ci': {'required_check_run_ids': {suffix: str(501 + offset) for offset, (_, suffix) in enumerate(ORDINARY)}}}),
                                                      'EXTERNAL_ID': EXTERNAL_ID, 'GH_TOKEN': 'test-read-only',
                                                      'installation_token': 'test-no-real-secret', 'GITHUB_STEP_SUMMARY': str(root / 'summary')})
            return result, json.loads(fixture.read_text())

    def test_publisher_later_bad_authorizing_attempt_fails_existing_five_without_creation(self) -> None:
        for conclusion in ('failure', 'cancelled', 'timed_out', None):
            with self.subTest(conclusion=conclusion):
                data = snapshot()
                prefix = f'repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}'
                retry = copy.deepcopy(data[prefix + '/attempts/1'])
                retry.update(run_attempt=2, conclusion=conclusion, triggering_actor={'login': 'bb-connor'})
                data[prefix], data[prefix + '/attempts/2'] = retry, copy.deepcopy(retry)
                result, observed = self.run_publisher_guard(data)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                checks = observed[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs']
                self.assertEqual(len(checks), 5)
                self.assertTrue(all(c['conclusion'] == 'failure' for c in checks), result.stderr)
                self.assertEqual([c['external_id'] for c in checks], [c['external_id'] for c in snapshot()[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs']])
                self.assertEqual([c['output']['text'] for c in checks], [c['output']['text'] for c in snapshot()[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs']])

    def test_publisher_unbound_sibling_failure_cannot_withdraw_authority(self) -> None:
        data = snapshot()
        sibling = copy.deepcopy(data[f'repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}'])
        sibling.update(id=302, conclusion='failure')
        data[f'repos/{REPOSITORY}/actions/runs/302'] = sibling
        data[f'repos/{REPOSITORY}/actions/workflows/enterprise-evidence-finalizer.yml/runs']['workflow_runs'].append(sibling)
        result, observed = self.run_publisher_guard(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(observed[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs'], data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs'])

    def test_publisher_later_success_cannot_restore_bad_authorizing_history(self) -> None:
        data = snapshot()
        prefix = f'repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}'
        bad = copy.deepcopy(data[prefix + '/attempts/1'])
        bad.update(run_attempt=2, conclusion='failure')
        latest = copy.deepcopy(bad)
        latest.update(run_attempt=3, conclusion='success')
        data[prefix], data[prefix + '/attempts/2'], data[prefix + '/attempts/3'] = latest, bad, copy.deepcopy(latest)
        result, observed = self.run_publisher_guard(data)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(all(c['conclusion'] == 'failure' for c in observed[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs']))

    def test_publisher_missing_app_anchor_cannot_create_retry_authority(self) -> None:
        data = snapshot()
        data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs'] = {'total_count': 0, 'check_runs': []}
        result, observed = self.run_publisher_guard(data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(observed[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs'], [])

    def test_initial_own_publication_can_finish_before_workflow_completion(self) -> None:
        data = snapshot()
        prefix = f'repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}'
        for key in (prefix, prefix + '/attempts/1'):
            data[key].update(status='in_progress', conclusion=None)
        jobs = data[prefix + '/attempts/1/jobs']['jobs']
        jobs[-1].update(status='in_progress', conclusion=None)
        result, observed = self.run_publisher_guard(data, own_run=FINALIZER_RUN)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(observed[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs'], data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs'])

    def test_publisher_rejects_untrusted_retry_binding_without_mutating_checks(self) -> None:
        for mutation in ('source_ci', 'original_actor', 'original_job', 'first_attempt_url', 'retry_head'):
            with self.subTest(mutation=mutation):
                data = snapshot()
                prefix = f'repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}'
                retry = copy.deepcopy(data[prefix + '/attempts/1'])
                retry.update(run_attempt=2, conclusion='failure')
                data[prefix], data[prefix + '/attempts/2'] = retry, copy.deepcopy(retry)
                authority = data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs'][-1]
                if mutation == 'source_ci':
                    metadata = json.loads(authority['output']['text'])
                    metadata['source_ci']['run_id'] = '999'
                    authority['output']['text'] = json.dumps(metadata)
                elif mutation == 'original_actor': data[prefix + '/attempts/1']['triggering_actor'] = {'login': 'bb-connor'}
                elif mutation == 'original_job': data[prefix + '/attempts/1/jobs']['jobs'][0]['conclusion'] = 'failure'
                elif mutation == 'first_attempt_url': authority['details_url'] = authority['details_url'].replace('/attempts/1', '/attempts/2')
                else: data[prefix + '/attempts/2']['head_sha'] = SOURCE
                result, observed = self.run_publisher_guard(data)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(observed[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs'], data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs'])

    def test_publisher_existing_failure_never_returns_success_or_changes_metadata(self) -> None:
        data = snapshot()
        data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs'][-1]['conclusion'] = 'failure'
        result, observed = self.run_publisher_guard(data)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(observed[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs'], data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs'])

    def own_healthy_retry(self, attempt: int = 2) -> dict:
        data = snapshot()
        prefix = f'repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}'
        retry = copy.deepcopy(data[prefix + '/attempts/1'])
        retry.update(run_attempt=attempt, status='in_progress', conclusion=None,
                     triggering_actor={'login': 'bb-connor'})
        data[prefix], data[prefix + f'/attempts/{attempt}'] = retry, copy.deepcopy(retry)
        jobs = copy.deepcopy(data[prefix + '/attempts/1/jobs'])
        for job in jobs['jobs']: job['workflow_name'] = retry['display_title']
        jobs['jobs'][-1].update(status='in_progress', conclusion=None)
        data[prefix + f'/attempts/{attempt}/jobs'] = jobs
        return data

    def test_own_healthy_retry_preserves_existing_authority_and_original_metadata(self) -> None:
        data = self.own_healthy_retry()
        result, observed = self.run_publisher_guard(data, own_run=FINALIZER_RUN, own_attempt=2)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(observed, data, 'healthy authenticated retry must not write any authority')

    def test_full_healthy_retry_preserves_positive_metadata_and_first_attempt_provenance_bytes(self) -> None:
        data = self.own_healthy_retry()
        checks = data[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs']
        for check in checks:
            check['details_url'] = f'https://github.com/{REPOSITORY}/actions/runs/{FINALIZER_RUN}/attempts/1'
            if check['name'] == 'Security contract':
                check['output'].update(title='Chio security authority', summary=f'Dedicated chio-security-authority approval for {EXTERNAL_ID}.')
            else:
                source_name = check['name'].removeprefix('Security mirror / ')
                check['output'].update(title='Chio trusted Actions mirror', summary=f'Trusted mirror of authenticated {source_name} for {EXTERNAL_ID}.')
            data[f'repos/{REPOSITORY}/check-runs/{check["id"]}'] = copy.deepcopy(check)
        result, observed = self.run_publisher_guard(data, own_run=FINALIZER_RUN, own_attempt=2, full_publication=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(observed, data, 'healthy retry altered positive output bytes, IDs, source CI or attempt-1 provenance')

    def test_own_current_retry_cannot_hide_an_older_bad_attempt(self) -> None:
        data = self.own_healthy_retry(attempt=3)
        prefix = f'repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}'
        bad = copy.deepcopy(data[prefix + '/attempts/1'])
        bad.update(run_attempt=2, conclusion='cancelled')
        data[prefix + '/attempts/2'] = bad
        result, observed = self.run_publisher_guard(data, own_run=FINALIZER_RUN, own_attempt=3)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(all(c['conclusion'] == 'failure' for c in observed[f'repos/{REPOSITORY}/commits/{MERGE}/check-runs']['check_runs']))

    def test_in_progress_peer_or_unproven_own_retry_cannot_pass(self) -> None:
        for mutation in ('peer', 'attempt', 'predecessor', 'job_head', 'job_run', 'job_title'):
            with self.subTest(mutation=mutation):
                data = self.own_healthy_retry()
                jobs = data[f'repos/{REPOSITORY}/actions/runs/{FINALIZER_RUN}/attempts/2/jobs']['jobs']
                if mutation == 'predecessor': jobs[0]['conclusion'] = 'failure'
                elif mutation == 'job_head': jobs[0]['head_sha'] = SOURCE
                elif mutation == 'job_run': jobs[0]['run_id'] = 999
                elif mutation == 'job_title': jobs[0]['workflow_name'] = 'Enterprise evidence finalizer'
                result, observed = self.run_publisher_guard(data, own_run=901 if mutation == 'peer' else FINALIZER_RUN,
                                                            own_attempt=3 if mutation == 'attempt' else 2)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(observed, data, 'unproven current retry cannot mutate existing authority')

    def test_retry_cannot_create_success_in_either_positive_post_branch(self) -> None:
        body = next(step['run'] for step in workflow('enterprise-evidence-finalizer.yml')['jobs']['publish-security-contract']['steps']
                    if step.get('name') == 'Reconcile exact five-context merge authority')
        body = body[body.index('publish_success_authority() {'):]
        for variable in ('mirror_check', 'check_run'):
            with self.subTest(branch=variable):
                start = body.index(variable + '="$({')
                post = body.index('--request POST', start)
                end = body.index('})"', post) + 3
                prefix = body[:start].rstrip().splitlines()[-1].strip()
                fragment = (prefix + '\n' if prefix.startswith('test "${FINALIZER_RUN_ATTEMPT}"') else '') + body[start:end]
                with tempfile.TemporaryDirectory(prefix='chio-no-retry-positive-') as raw:
                    root = Path(raw)
                    calls = root / 'calls'
                    curl = root / 'curl'
                    curl.write_text('#!/usr/bin/env python3\nimport os,pathlib\npathlib.Path(os.environ["POST_CALLS"]).write_text("POST attempted")\nprint("{}")\n')
                    curl.chmod(0o755)
                    env = os.environ | {'PATH': str(root) + os.pathsep + os.environ['PATH'], 'POST_CALLS': str(calls),
                                        'FINALIZER_RUN_ATTEMPT': '2', 'GH_TOKEN': 'offline', 'installation_token': 'offline',
                                        'GITHUB_REPOSITORY': REPOSITORY, 'mirror_payload': '{}', 'check_payload': '{}'}
                    result = subprocess.run(['bash', '-c', 'set -euo pipefail\n' + fragment], env=env,
                                            capture_output=True, text=True, check=False)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertFalse(calls.exists(), 'a later attempt reached a positive-authority POST')
                    env['FINALIZER_RUN_ATTEMPT'] = '1'
                    initial = subprocess.run(['bash', '-c', 'set -euo pipefail\n' + fragment], env=env,
                                             capture_output=True, text=True, check=False)
                    self.assertEqual(initial.returncode, 0, initial.stdout + initial.stderr)
                    self.assertTrue(calls.exists(), 'first-attempt positive publication was suppressed')


PRIOR_MERGE, REGENERATED_MERGE = "7" * 40, "9" * 40
PRIOR_CI_RUN = 200
HEAD_REF = "integration/process-security-m4"
ACTIONS_TOKEN, INSTALLATION_TOKEN = "offline-actions-token", "offline-installation-token"
CHECK_RUN_APPS = {
    ACTIONS_TOKEN: {"id": 15368, "slug": "github-actions"},
    INSTALLATION_TOKEN: {"id": APP_ID, "slug": "chio-security-authority"},
}
PUBLICATION_PROBE = "success publication reached"
BUILD_MIRROR_QUERY = "check_name=Security%20mirror%20%2F%20Build%2C%20lint%2C%20test"
CI_HISTORY_QUERY = f"actions/workflows/ci.yml/runs?event=pull_request&head_sha={EVIDENCE}&per_page=100&page=1"
# Observed REST state after main advanced past an open pull request: the pull
# still reported the old base.sha and its test merge kept the old base parent.
STALE_BASE, ADVANCED_MAIN = "b5b44d6c20605087d35b7e5f42fb679e0ac8e35f", "eb6c77b835acea73346aeff6a9e64ecec7a68f01"
STALE_HEAD, STALE_MERGE, STALE_TREE = (
    "161132fdaa4232d10003d47afb23a5f4efb3ff53", "baf9ac4159d4d242e7f08dc4ebb11447fd777475",
    "1a6c8898d7bfe5f4520be9349e1005aa4d5c86b5",
)


def foreign_mirror(head_sha: str) -> dict:
    # Shape of a check run that an unrelated Actions workflow posted under a
    # mirror name with the Actions token (observed check run 113139755293).
    return {
        "id": 113139755293, "name": "Security mirror / Build, lint, test", "head_sha": head_sha,
        "external_id": "e8b6b49f-75e8-5c85-8b08-87b6cfd6ec76", "status": "completed", "conclusion": "success",
        "started_at": "2026-10-08T03:50:04Z", "completed_at": "2026-10-08T03:50:04Z",
        "output": {"title": None, "summary": None, "text": None, "annotations_count": 0},
        "check_suite": {"id": 102200875191}, "app": {"id": 15368, "slug": "github-actions"},
    }


LOGGED_GH = r'''#!/usr/bin/env -S python3 -I -S
import os,sys
path=next((a for a in sys.argv[1:] if a.startswith('repos/')),'')
if path:
    with open(os.environ['API_LOG'],'a') as log: log.write('GET '+path+'\n')
os.execv(sys.executable,[sys.executable,'-I','-S',os.environ['FAKE_GH_PATH']]+sys.argv[1:])
'''

CHECK_STORE_CURL = r'''#!/usr/bin/env -S python3 -I -S
import json,os,sys,pathlib,urllib.parse
args=sys.argv[1:]
url=next(a for a in args if a.startswith('https://api.github.com/'))
parts=urllib.parse.urlsplit(url)
path=parts.path.lstrip('/')
query={key:values[0] for key,values in urllib.parse.parse_qs(parts.query).items()}
method=args[args.index('--request')+1] if '--request' in args else 'GET'
token=next((a.split('Bearer ',1)[1] for a in args if a.startswith('Authorization: Bearer ')),'')
with open(os.environ['API_LOG'],'a') as log: log.write(method+' '+path+('?'+parts.query if parts.query else '')+'\n')
fixture=pathlib.Path(os.environ['API_FIXTURE']);data=json.loads(fixture.read_text())
prefix='repos/'+os.environ['GITHUB_REPOSITORY']+'/'
def fail(message):
    sys.stderr.write(message+'\n');sys.exit(22)
def page(records):
    size=int(query.get('per_page','30'));number=int(query.get('page','1'))
    return records[(number-1)*size:number*size]
def stores():
    return [data[key]['check_runs'] for key in data if key.startswith(prefix+'commits/') and key.endswith('/check-runs')]
if method=='GET':
    segments=path[len(prefix):].split('/')
    if len(segments)==3 and segments[0]=='commits' and segments[2]=='check-runs':
        if query.get('filter')!='all': fail('unsupported check-run filter')
        runs=[c for c in data.get(path,{'check_runs':[]})['check_runs']
              if c['name']==query.get('check_name',c['name']) and str(c['app']['id'])==query.get('app_id',str(c['app']['id']))]
        print(json.dumps({'total_count':len(runs),'check_runs':page(runs)}));sys.exit(0)
    key=path+('?ref='+query['ref'] if 'ref' in query else '')
    if key not in data: fail('unprovided API '+key)
    result=data[key]
    if isinstance(result,list):
        result=page([r for r in result if path!=prefix+'pulls' or query.get('state','open') in ('all',r['state'])])
    elif path.endswith('/runs') and 'workflow_runs' in result:
        runs=[r for r in result['workflow_runs'] if all(str(r.get(field))==query[field] for field in ('event','head_sha') if field in query)]
        result={'total_count':len(runs),'workflow_runs':page(runs)}
    elif query.get('page','1')!='1': fail('unexpected missing API page')
    print(json.dumps(result));sys.exit(0)
apps=json.loads(os.environ['CHECK_RUN_APPS'])
if token not in apps: fail('token cannot write check runs')
app=apps[token]
payload=json.loads(args[args.index('--data-binary')+1])
if method=='POST' and path==prefix+'check-runs':
    identifier=1+max([c['id'] for runs in stores() for c in runs]+[990000])
    check={'id':identifier,'name':payload['name'],'head_sha':payload['head_sha'],'external_id':payload.get('external_id'),
           'status':payload.get('status','queued'),'conclusion':payload.get('conclusion'),'completed_at':payload.get('completed_at'),
           'details_url':payload.get('details_url'),'output':payload.get('output',{}),'app':app,'check_suite':{'id':identifier+1}}
    store=data.setdefault(prefix+'commits/'+payload['head_sha']+'/check-runs',{'total_count':0,'check_runs':[]})
    store['check_runs'].append(check);store['total_count']=len(store['check_runs'])
elif method=='PATCH' and path.startswith(prefix+'check-runs/'):
    matches=[c for runs in stores() for c in runs if c['id']==int(path.rsplit('/',1)[1])]
    if len(matches)!=1: fail('unknown check run')
    check=matches[0]
    if check['app']['id']!=app['id']: fail('check run belongs to another app')
    for field in ('name','external_id','status','conclusion','completed_at','details_url','output'):
        if field in payload: check[field]=payload[field]
else: fail('unexpected mutation '+method+' '+path)
data[prefix+'check-runs/'+str(check['id'])]=check
fixture.write_text(json.dumps(data));print(json.dumps(check))
'''

# The fixtures hold only completed runs, so any poll means no run matched.
# Refusing at the first poll is the outcome the step reaches when its poll
# budget runs out, without the wall-clock wait.
POLL_LIMIT_SLEEP = "#!/usr/bin/env bash\nprintf 'sleep %s\\n' \"$*\" >> \"${API_LOG}\"\nexit 75\n"


class OfflineRun(NamedTuple):
    result: subprocess.CompletedProcess
    data: dict
    calls: list[str]
    output: str
    collected: dict[str, str]


def run_offline_step(script: str, data: dict, environment: dict[str, str], *, poll_limit: bool = False,
                     files: dict[str, bytes] | None = None, collect: tuple[str, ...] = ()) -> OfflineRun:
    with tempfile.TemporaryDirectory(prefix="chio-evidence-head-") as raw:
        root = Path(raw)
        fixture, log, output, binary = root / "api.json", root / "api.log", root / "output", root / "bin"
        fixture.write_text(json.dumps(data))
        log.write_text("")
        (root / "gh-fixture").write_text(FAKE_GH)
        binary.mkdir()
        tools = {"gh": LOGGED_GH, "curl": CHECK_STORE_CURL} | ({"sleep": POLL_LIMIT_SLEEP} if poll_limit else {})
        for name, source in tools.items():
            (binary / name).write_text(source)
            (binary / name).chmod(0o755)
        for name, content in (files or {}).items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(content)
        env = os.environ | {
            "PATH": str(binary) + os.pathsep + os.environ["PATH"], "API_FIXTURE": str(fixture), "API_LOG": str(log),
            "FAKE_GH_PATH": str(root / "gh-fixture"), "CHECK_RUN_APPS": json.dumps(CHECK_RUN_APPS),
            "COMMENT_FILE": str(root / "comment.md"), "GITHUB_OUTPUT": str(output), "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_REPOSITORY_OWNER": "bb-connor", "GITHUB_STEP_SUMMARY": str(root / "summary.md"),
            "RUNNER_TEMP": str(root),
        } | environment
        result = subprocess.run(["bash", "-c", script], cwd=root, env=env, capture_output=True, text=True,
                                check=False, timeout=300)
        collected = {name: (root / name).read_text() for name in collect if (root / name).exists()}
        return OfflineRun(result, json.loads(fixture.read_text()), log.read_text().splitlines(),
                          output.read_text() if output.exists() else "", collected)


def workflow_step(name: str, job: str, step: str) -> str:
    return next(item["run"] for item in workflow(name)["jobs"][job]["steps"] if item.get("name") == step)


def live_pull_request(number: int = PR, head: str = EVIDENCE, base: str = BASE, merge: str = MERGE,
                      head_ref: str = HEAD_REF) -> dict:
    repository = {"id": 1195888645, "full_name": REPOSITORY}
    return {
        "number": number, "state": "open", "merged": False, "draft": False, "merge_commit_sha": merge,
        "mergeable": True, "mergeable_state": "blocked", "user": {"login": "bb-connor"},
        "author_association": "OWNER", "labels": [],
        "head": {"label": f"bb-connor:{head_ref}", "ref": head_ref, "sha": head, "repo": repository},
        "base": {"label": "bb-connor:main", "ref": "main", "sha": base, "repo": repository},
    }


def live_tuple(live_merge: str = MERGE, main: str = BASE, base: str = BASE, head: str = EVIDENCE,
               tree: str = TREE, merges: tuple[str, ...] = (MERGE, PRIOR_MERGE, REGENERATED_MERGE)) -> dict:
    prefix = f"repos/{REPOSITORY}"
    pull = live_pull_request(head=head, base=base, merge=live_merge)
    data = {
        f"{prefix}/pulls/{PR}": pull,
        f"{prefix}/pulls": [copy.deepcopy(pull)],
        f"{prefix}/commits/{head}/pulls": [copy.deepcopy(pull)],
        f"{prefix}/git/ref/pull/{PR}/merge": {"ref": f"refs/pull/{PR}/merge", "object": {"type": "commit", "sha": live_merge}},
        f"{prefix}/git/ref/heads/main": {"ref": "refs/heads/main", "object": {"type": "commit", "sha": main}},
    }
    for merge in merges:
        data[f"{prefix}/git/commits/{merge}"] = {"sha": merge, "parents": [{"sha": base}, {"sha": head}], "tree": {"sha": tree}}
    return data


def pull_request_ci_run(run_id: int, title_merge: str, conclusion: str | None = "success", attempt: int = 1,
                        check_suite_id: int = 401, display_title: str | None = None) -> dict:
    repository = {"id": 1195888645, "full_name": REPOSITORY}
    return {
        "id": run_id, "name": "CI", "workflow_id": CI_WORKFLOW, "path": ".github/workflows/ci.yml",
        "display_title": display_title or f"CI N={PR} E={EVIDENCE} B={BASE} M={title_merge}",
        "event": "pull_request", "head_sha": EVIDENCE, "head_branch": HEAD_REF, "run_attempt": attempt,
        "status": "completed", "conclusion": conclusion, "check_suite_id": check_suite_id,
        "repository": repository, "head_repository": repository,
        "actor": {"login": "bb-connor"}, "triggering_actor": {"login": "bb-connor"},
        "created_at": "2026-10-06T00:00:00Z", "updated_at": "2026-10-06T00:04:00Z",
    }


def add_ci_runs(data: dict, *runs: dict) -> None:
    prefix = f"repos/{REPOSITORY}"
    listing = [copy.deepcopy(run) for run in sorted(runs, key=lambda run: run["id"], reverse=True)]
    data[f"{prefix}/actions/workflows/ci.yml/runs"] = {"total_count": len(listing), "workflow_runs": listing}
    for run in runs:
        data[f"{prefix}/actions/runs/{run['id']}"] = copy.deepcopy(run)
        data[f"{prefix}/actions/runs/{run['id']}/attempts/{run['run_attempt']}"] = copy.deepcopy(run)


def publication_binding(base: str = BASE, evidence: str = EVIDENCE, merge: str = MERGE, tree: str = TREE) -> str:
    binding = {
        "artifact": {"digest": "sha256:" + "6" * 64, "id": "811", "name": f"enterprise-linux-capture-{evidence}-401-1",
                     "size": "4096"},
        "authorized_source_sha": SOURCE, "base": {"ref": "main", "repository": REPOSITORY, "sha": base},
        "capture": {"actor": "github-actions[bot]", "definition_blob": "6" * 40, "issued_at_unix_ms": "1791244860000",
                    "job_id": "821", "run_attempt": "1", "run_id": "401", "workflow_id": "105"},
        "ci": {"aggregate_check_run_id": "505",
               "merge_binding": {"artifact_digest": "sha256:" + "7" * 64, "artifact_id": "812",
                                 "attestation_bundle_sha256": "8" * 64, "binding_sha256": "9" * 64},
               "required_check_run_ids": {"build": "501", "deny": "504", "msrv": "502", "vet": "503"},
               "run_attempt": "1", "run_id": str(CI_RUN), "workflow_id": str(CI_WORKFLOW)},
        "committed_binding_digest": "a" * 64, "configuration_digest": "b" * 64,
        "controller": {"actor": "bb-connor", "definition_blob": "6" * 40, "issued_at_unix_ms": "1791244800000",
                       "run_attempt": "1", "run_id": "111", "workflow_id": "104"},
        "evidence_sha": evidence,
        "gate_result_digests": {name: "c" * 64 for name in (
            "broker_boundary", "cage_enforcement", "committed_adversarial_evidence", "key_log_transparency",
            "linux_adversarial_controls", "migration_state_store", "runner_contract")},
        "inventory_digest": "d" * 64, "labels_digest": hashlib.sha256(b"[]").hexdigest(),
        "merge_commit_sha": merge, "merge_tree_sha": tree, "pr_number": str(PR), "repository": REPOSITORY,
        "runner": {"arch": "X64", "labels_digest": "e" * 64, "name": "GitHub Actions 7", "os": "Linux"},
        "schema": "chio.security-check-publication.v1", "security_definition_sha": DEFINITION,
    }
    return json.dumps(binding, sort_keys=True, separators=(",", ":"))


def checks_on(data: dict, name: str, app_id: int, conclusion: str) -> list[dict]:
    prefix = f"repos/{REPOSITORY}/commits/"
    return [check for key, store in data.items() if key.startswith(prefix) and key.endswith("/check-runs")
            for check in store["check_runs"] if check["name"] == name and check["app"]["id"] == app_id
            and check["status"] == "completed" and check["conclusion"] == conclusion]


def security_contract_failures(data: dict) -> list[dict]:
    return checks_on(data, "Security contract", APP_ID, "failure")


def publisher_body() -> str:
    return workflow_step("enterprise-evidence-finalizer.yml", "publish-security-contract",
                         "Reconcile exact five-context merge authority")


def publication_head_revalidation() -> str:
    body = publisher_body()
    return body[body.index("revalidate_live_publication_head() {"):body.index("list_actions_mirror_checks() {")]


def publisher_environment() -> dict[str, str]:
    return {
        "AUTHORIZED_SOURCE_SHA": SOURCE, "CI_RUN_ATTEMPT": "1", "CI_RUN_ID": str(CI_RUN),
        "CI_WORKFLOW_ID": str(CI_WORKFLOW), "EVIDENCE_SHA": EVIDENCE, "EXTERNAL_ID": EXTERNAL_ID,
        "GH_TOKEN": ACTIONS_TOKEN, "MERGE_COMMIT_SHA": MERGE, "PR_NUMBER": str(PR),
        "SECURITY_APP_ID": str(APP_ID), "SECURITY_DEFINITION_SHA": DEFINITION,
        "installation_token": INSTALLATION_TOKEN, "canonical_binding": publication_binding(),
    }


def revalidate_publication_head(data: dict, evidence: str = EVIDENCE, merge: str = MERGE, base: str = BASE,
                                tree: str = TREE) -> OfflineRun:
    script = ("set -euo pipefail\nshopt -s inherit_errexit\n" + publication_head_revalidation()
              + f'\nrevalidate_live_publication_head\necho "{PUBLICATION_PROBE}"\n')
    return run_offline_step(script, data, {"GH_TOKEN": ACTIONS_TOKEN, "PR_NUMBER": str(PR), "EVIDENCE_SHA": evidence,
                                           "canonical_binding": publication_binding(base, evidence, merge, tree)})


def reconcile_bad_ci_then_publish(data: dict) -> OfflineRun:
    body = publisher_body()
    script = ("set -euo pipefail\nshopt -s inherit_errexit\n" + publication_head_revalidation()
              + body[body.index("list_namespace_checks() {"):body.index("reconcile_bad_authorizing_finalizer() {")]
              + f'publish_success_authority() {{ echo "{PUBLICATION_PROBE}"; }}\n'
              + body[body.index('\nreconcile_bad_ci\nif test "${bad_ci_observed}" = false; then'):])
    return run_offline_step(script, data, publisher_environment())


def bad_ci_fixture(*extra_runs: dict, mirrors: tuple[dict, ...] = ()) -> dict:
    data = live_tuple()
    add_ci_runs(data, pull_request_ci_run(CI_RUN, MERGE), *extra_runs)
    data[f"repos/{REPOSITORY}/commits/{MERGE}/check-runs"] = {"total_count": len(mirrors), "check_runs": list(mirrors)}
    return data


def prior_failed_ci_run(title_merge: str, display_title: str | None = None) -> dict:
    return pull_request_ci_run(PRIOR_CI_RUN, title_merge, conclusion="failure", check_suite_id=400,
                               display_title=display_title)


def authenticate_ci(data: dict, recorded_merge: str) -> OfflineRun:
    body = workflow_step("enterprise-evidence-finalizer.yml", "authorize-security-check-publication",
                         "Authenticate exact successful current CI run")
    return run_offline_step(body, data, {
        "BASE_REF": "main", "BASE_SHA": BASE, "CI_WORKFLOW_ID": str(CI_WORKFLOW), "EVIDENCE_SHA": EVIDENCE,
        "GH_TOKEN": ACTIONS_TOKEN, "HEAD_REF": HEAD_REF, "MERGE_COMMIT_SHA": recorded_merge, "MERGE_TREE_SHA": TREE,
        "PR_NUMBER": str(PR),
    }, poll_limit=True)


def ci_authentication_fixture(live_merge: str = MERGE) -> dict:
    prefix = f"repos/{REPOSITORY}"
    data = live_tuple(live_merge=live_merge)
    add_ci_runs(data, pull_request_ci_run(CI_RUN, MERGE))
    jobs = []
    for identifier, name in enumerate([name for name, _ in ORDINARY] + ["Security contract"], 501):
        jobs.append({"id": identifier, "run_id": CI_RUN, "name": name, "head_sha": EVIDENCE, "status": "completed",
                     "conclusion": "success", "check_run_url": f"https://api.github.com/{prefix}/check-runs/{identifier}"})
        data[f"{prefix}/check-runs/{identifier}"] = {
            "id": identifier, "name": name, "head_sha": EVIDENCE, "status": "completed", "conclusion": "success",
            "check_suite": {"id": 401}, "app": {"id": 15368, "slug": "github-actions"}}
    data[f"{prefix}/actions/runs/{CI_RUN}/attempts/1/jobs"] = {"total_count": len(jobs), "jobs": jobs}
    return data


def stale_base_tuple(main: str) -> dict:
    return live_tuple(live_merge=STALE_MERGE, main=main, base=STALE_BASE, head=STALE_HEAD, tree=STALE_TREE,
                      merges=(STALE_MERGE,))


class PublisherEvidenceHeadOriginalRedTests(unittest.TestCase):
    def test_ci_authentication_survives_same_parent_tree_merge_regeneration(self) -> None:
        control = authenticate_ci(ci_authentication_fixture(), MERGE)
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertIn(f"ci_run_id={CI_RUN}\n", control.output)
        commits = f"repos/{REPOSITORY}/git/commits/"
        for recorded in (MERGE, REGENERATED_MERGE):
            with self.subTest(recorded_merge=recorded):
                data = ci_authentication_fixture(live_merge=REGENERATED_MERGE)
                self.assertEqual({key: value for key, value in data[commits + REGENERATED_MERGE].items() if key != "sha"},
                                 {key: value for key, value in data[commits + MERGE].items() if key != "sha"})
                run = authenticate_ci(data, recorded)
                self.assertIn(f"GET repos/{REPOSITORY}/{CI_HISTORY_QUERY}", run.calls)
                if recorded == MERGE:
                    self.assertIn(f"GET repos/{REPOSITORY}/git/ref/pull/{PR}/merge", run.calls)
                self.assertEqual(run.result.returncode, 0,
                                 "a test merge regenerated with the same parents and tree left the exact successful "
                                 f"CI run unbindable (polls for a matching run: {run.calls.count('sleep 30')})")
                self.assertIn(f"ci_run_id={CI_RUN}\n", run.output)

    def test_publication_head_revalidation_survives_same_parent_tree_merge_regeneration(self) -> None:
        control = revalidate_publication_head(live_tuple())
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertIn(PUBLICATION_PROBE, control.result.stdout)
        run = revalidate_publication_head(live_tuple(live_merge=REGENERATED_MERGE))
        self.assertIn(f"GET repos/{REPOSITORY}/git/ref/pull/{PR}/merge", run.calls)
        self.assertEqual(run.result.returncode, 0, "publication refused a live test merge with the recorded parents and tree")
        self.assertIn(PUBLICATION_PROBE, run.result.stdout)

    def test_failed_ci_under_a_prior_test_merge_blocks_publication_for_the_same_evidence(self) -> None:
        healthy = reconcile_bad_ci_then_publish(bad_ci_fixture())
        self.assertEqual(healthy.result.returncode, 0, healthy.result.stderr)
        self.assertIn(PUBLICATION_PROBE, healthy.result.stdout)
        current = reconcile_bad_ci_then_publish(bad_ci_fixture(prior_failed_ci_run(MERGE)))
        self.assertNotEqual(current.result.returncode, 0)
        self.assertNotIn(PUBLICATION_PROBE, current.result.stdout)
        self.assertEqual(len(security_contract_failures(current.data)), 1, current.result.stderr)
        prior = reconcile_bad_ci_then_publish(bad_ci_fixture(prior_failed_ci_run(PRIOR_MERGE)))
        self.assertIn(f"GET repos/{REPOSITORY}/{CI_HISTORY_QUERY}", prior.calls)
        self.assertNotIn(PUBLICATION_PROBE, prior.result.stdout,
                         f"failed CI run {PRIOR_CI_RUN} on the same evidence head under a prior test merge did not block publication")
        self.assertNotEqual(prior.result.returncode, 0)
        self.assertEqual(len(security_contract_failures(prior.data)), 1, prior.result.stderr)

    def test_foreign_mirror_cannot_block_the_bad_ci_security_contract_tombstone(self) -> None:
        clean = reconcile_bad_ci_then_publish(bad_ci_fixture(prior_failed_ci_run(MERGE)))
        self.assertEqual(len(security_contract_failures(clean.data)), 1, clean.result.stderr)
        polluted = reconcile_bad_ci_then_publish(bad_ci_fixture(prior_failed_ci_run(MERGE), mirrors=(foreign_mirror(MERGE),)))
        self.assertTrue(any(BUILD_MIRROR_QUERY in call for call in polluted.calls), polluted.calls)
        self.assertNotIn(PUBLICATION_PROBE, polluted.result.stdout)
        self.assertEqual(len(security_contract_failures(polluted.data)), 1,
                         "a foreign Actions mirror without the required external id stopped bad-CI revocation "
                         "before the Security contract tombstone")
        self.assertTrue(any(check["id"] == 113139755293 for key, store in polluted.data.items()
                            if key.endswith("/check-runs") for check in store["check_runs"]))

    def test_publication_head_revalidation_refuses_main_advanced_past_a_stale_pull_base(self) -> None:
        stale = (STALE_HEAD, STALE_MERGE, STALE_BASE, STALE_TREE)
        control = revalidate_publication_head(stale_base_tuple(STALE_BASE), *stale)
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertIn(PUBLICATION_PROBE, control.result.stdout)
        run = revalidate_publication_head(stale_base_tuple(ADVANCED_MAIN), *stale)
        self.assertIn(f"GET repos/{REPOSITORY}/git/commits/{STALE_MERGE}", run.calls)
        self.assertNotIn(PUBLICATION_PROBE, run.result.stdout,
                         f"publication accepted base {STALE_BASE} after main advanced to {ADVANCED_MAIN}")
        self.assertNotEqual(run.result.returncode, 0)

    def test_capture_revalidation_refuses_main_advanced_past_a_stale_pull_base(self) -> None:
        prefix = f"repos/{REPOSITORY}"
        issued = int(time.time()) - 120
        body = workflow_step("enterprise-evidence-finalizer.yml", "validate-capture",
                             "Revalidate live authorization and issuance freshness")
        script = (body.replace("${{ steps.validate.outputs.authorized_source_sha }}", SOURCE)
                  .replace("${{ github.event.repository.default_branch }}", "main"))
        self.assertNotIn("${{", script)

        def capture(main: str) -> OfflineRun:
            data = stale_base_tuple(main) | {
                f"{prefix}/actions/workflows/enterprise-evidence-controller.yml": {
                    "id": 104, "path": ".github/workflows/enterprise-evidence-controller.yml", "state": "active"},
                f"{prefix}/actions/runs/111": {
                    "id": 111, "workflow_id": 104, "path": ".github/workflows/enterprise-evidence-controller.yml",
                    "event": "pull_request_target", "status": "completed", "conclusion": "success",
                    "head_sha": DEFINITION, "head_branch": "main", "run_attempt": 1,
                    "actor": {"login": "bb-connor"}, "triggering_actor": {"login": "bb-connor"},
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(issued))},
                f"{prefix}/contents/.github/workflows/enterprise-evidence-controller.yml?ref={DEFINITION}": {"sha": "6" * 40},
                f"{prefix}/commits/{STALE_HEAD}": {"sha": STALE_HEAD, "parents": [{"sha": SOURCE}], "files": [
                    {"filename": f"audits/evidence/enterprise-linux/{name}", "status": "modified"} for name in (
                        "enterprise-migration-canary.json", "enterprise-migration-canary.json.sha256",
                        "enterprise-migration-binding-digest.txt")]},
                f"{prefix}/git/commits/{STALE_HEAD}": {"sha": STALE_HEAD, "parents": [{"sha": SOURCE}], "tree": {"sha": "e0" * 20}},
            }
            for parent, component, child in (("e0", "audits", "e1"), ("e1", "evidence", "e2"),
                                              ("e2", "enterprise-linux", "e3")):
                data[f"{prefix}/git/trees/{parent * 20}"] = {"sha": parent * 20, "truncated": False, "tree": [
                    {"path": component, "mode": "040000", "type": "tree", "sha": child * 20}]}
            data[f"{prefix}/git/trees/{'e3' * 20}"] = {"sha": "e3" * 20, "truncated": False, "tree": [
                {"path": name, "mode": "100644", "type": "blob", "sha": "f" * 40} for name in (
                    "enterprise-migration-binding-digest.txt", "enterprise-migration-canary.json",
                    "enterprise-migration-canary.json.sha256")]}
            return run_offline_step(script, data, {
                "AUTHORIZED_SOURCE_SHA": SOURCE, "ENTERPRISE_SECURITY_DEFINITION_SHA": DEFINITION,
                "GH_TOKEN": ACTIONS_TOKEN, "BASE_REF": "main", "BASE_REPOSITORY": REPOSITORY, "BASE_SHA": STALE_BASE,
                "CAPTURE_ISSUED_AT_UNIX_MS": str((issued + 60) * 1000), "CAPTURE_RUN_ATTEMPT": "1",
                "CAPTURE_RUN_ID": "401", "CONTROLLER_ACTOR": "bb-connor", "CONTROLLER_DEFINITION_BLOB": "6" * 40,
                "CONTROLLER_ISSUED_AT_UNIX_MS": str(issued * 1000), "CONTROLLER_RUN_ATTEMPT": "1",
                "CONTROLLER_RUN_ID": "111", "CONTROLLER_WORKFLOW_ID": "104",
                "LABELS_DIGEST": hashlib.sha256(b"[]").hexdigest(), "MERGE_COMMIT_SHA": STALE_MERGE,
                "MERGE_TREE_SHA": STALE_TREE, "PR_NUMBER": str(PR), "SECURITY_DEFINITION_SHA": DEFINITION,
                "SOURCE_REPOSITORY": REPOSITORY, "SOURCE_SHA": STALE_HEAD,
            })

        control = capture(STALE_BASE)
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertIn(f"GET repos/{REPOSITORY}/git/trees/{'e3' * 20}", control.calls)
        run = capture(ADVANCED_MAIN)
        self.assertIn(f"GET repos/{REPOSITORY}/git/commits/{STALE_MERGE}", run.calls)
        self.assertNotEqual(run.result.returncode, 0,
                            f"capture revalidation accepted base {STALE_BASE} after main advanced to {ADVANCED_MAIN}")


REVOKER_BLOB = "4" * 40


def revoker_run(run_id: int, event: str) -> dict:
    repository = {"id": 1195888645, "full_name": REPOSITORY}
    return {
        "id": run_id, "workflow_id": 103, "path": ".github/workflows/security-contract-revocation.yml", "event": event,
        "status": "in_progress", "conclusion": None, "head_sha": DEFINITION, "head_branch": "main", "run_attempt": 1,
        "actor": {"login": "bb-connor"}, "triggering_actor": {"login": "bb-connor"},
        "repository": repository, "head_repository": repository,
    }


def revoker_fixture(live_merge: str = MERGE, mirrors: tuple[dict, ...] = ()) -> dict:
    prefix = f"repos/{REPOSITORY}"
    data = live_tuple(live_merge=live_merge)
    data[f"{prefix}/contents/.github/workflows/security-contract-revocation.yml?ref={DEFINITION}"] = {"sha": REVOKER_BLOB}
    data[f"{prefix}/commits/{MERGE}/check-runs"] = {"total_count": len(mirrors), "check_runs": list(mirrors)}
    return data


def revoke_five_contexts(data: dict, event_name: str) -> OfflineRun:
    body = workflow_step("security-contract-revocation.yml", "revoke-security-contract",
                         "Revoke exact Actions mirrors and dedicated App namespace")
    script = body[:body.index('private_key="${RUNNER_TEMP}')] + body[body.index("list_checks() {"):]
    manual = event_name == "workflow_dispatch"
    return run_offline_step(script, data, {
        "AUTHORIZED_SOURCE_SHA": SOURCE, "BASE_SHA": BASE, "CREATE_MISSING": "true", "DEFAULT_BRANCH": "main",
        "EVIDENCE_SHA": EVIDENCE, "EVENT_NAME": event_name, "GH_TOKEN": ACTIONS_TOKEN,
        "LIVE_AUTHORIZED_SOURCE_SHA": SOURCE, "LIVE_COMMITTED_EVIDENCE_SHA": "0" * 40 if manual else EVIDENCE,
        "LIVE_SECURITY_DEFINITION_SHA": DEFINITION, "MERGE_COMMIT_SHA": MERGE, "MERGE_TREE_SHA": TREE,
        "PR_NUMBER": str(PR), "REASON": "operator-security-revocation" if manual else "ci-regression",
        "REVOKER_REF": "refs/heads/main", "REVOKER_SHA": DEFINITION, "SECURITY_APP_ID": str(APP_ID),
        "SECURITY_APP_INSTALLATION_ID": "1", "SECURITY_DEFINITION_SHA": DEFINITION,
        "installation_token": INSTALLATION_TOKEN,
    })


def bind_manual_revocation(data: dict) -> OfflineRun:
    body = workflow_step("security-contract-revocation.yml", "bind-revocation", "Bind frozen manual revocation")
    return run_offline_step(body, data, {
        "AUTHORIZED_SOURCE_SHA": SOURCE, "DEFAULT_BRANCH": "main", "EVIDENCE_SHA": EVIDENCE, "GH_TOKEN": ACTIONS_TOKEN,
        "MERGE_COMMIT_SHA": MERGE, "PR_NUMBER": str(PR), "REASON": "operator-security-revocation",
        "REVOKER_ACTOR": "bb-connor", "REVOKER_REF": "refs/heads/main", "REVOKER_RUN_ID": "902",
        "REVOKER_SHA": DEFINITION, "REVOKER_TRIGGERING_ACTOR": "bb-connor", "RUN_ATTEMPT": "1",
        "SECURITY_DEFINITION_SHA": DEFINITION,
    })


def failed_ci_listener_fixture(event_run: dict, jobs: list[dict], live_merge: str = MERGE,
                               earlier_attempts: tuple[dict, ...] = ()) -> dict:
    prefix = f"repos/{REPOSITORY}"
    data = revoker_fixture(live_merge=live_merge)
    run_id, attempt = event_run["id"], event_run["run_attempt"]
    data[f"{prefix}/actions/runs/{run_id}"] = copy.deepcopy(event_run)
    for record in (*earlier_attempts, event_run):
        data[f"{prefix}/actions/runs/{run_id}/attempts/{record['run_attempt']}"] = copy.deepcopy(record)
    data[f"{prefix}/actions/runs/{run_id}/attempts/{attempt}/jobs"] = {"total_count": len(jobs), "jobs": jobs}
    data[f"{prefix}/actions/runs/{run_id}/artifacts"] = {"total_count": 0, "artifacts": []}
    data[f"{prefix}/actions/runs/901/attempts/1"] = revoker_run(901, "workflow_run")
    for ref in (SOURCE, EVIDENCE, MERGE):
        data[f"{prefix}/contents/.github/workflows/ci.yml?ref={ref}"] = {"sha": "3" * 40}
    return data


def failed_builder_jobs(run_id: int) -> list[dict]:
    return [{"id": 509, "name": "attest exact pull request merge binding", "run_id": run_id, "head_sha": EVIDENCE,
             "status": "completed", "conclusion": "failure", "workflow_name": "CI"},
            {"id": 501, "name": "Build, lint, test", "run_id": run_id, "head_sha": EVIDENCE,
             "status": "completed", "conclusion": "failure", "workflow_name": "CI"}]


def bind_failed_ci(data: dict, event_run: dict) -> OfflineRun:
    body = workflow_step("security-contract-revocation.yml", "bind-revocation", "Bind later failed CI rerun to existing authority")
    return run_offline_step(body, data, {
        "AUTHORIZED_SOURCE_SHA": SOURCE, "COMMITTED_EVIDENCE_SHA": EVIDENCE, "DEFAULT_BRANCH": "main",
        "EVENT_ACTION": "completed", "EVENT_CONCLUSION": event_run["conclusion"] or "",
        "EVENT_RUN_ATTEMPT": str(event_run["run_attempt"]), "EVENT_RUN_ID": str(event_run["id"]),
        "EVENT_WORKFLOW_ID": str(CI_WORKFLOW), "GH_TOKEN": ACTIONS_TOKEN, "LISTENER_REF": "refs/heads/main",
        "LISTENER_RUN_ATTEMPT": "1", "LISTENER_RUN_ID": "901", "LISTENER_SHA": DEFINITION,
        "REPOSITORY_ID": "1195888645", "REPOSITORY_OWNER_ID": "1", "SECURITY_APP_ID": str(APP_ID),
        "SECURITY_DEFINITION_SHA": DEFINITION,
    })


class RevokerEvidenceHeadOriginalRedTests(unittest.TestCase):
    def test_foreign_mirror_cannot_block_the_revoker_security_contract_tombstone(self) -> None:
        for event_name in ("workflow_run", "workflow_dispatch"):
            with self.subTest(event=event_name):
                clean = revoke_five_contexts(revoker_fixture(), event_name)
                self.assertEqual(clean.result.returncode, 0, clean.result.stderr)
                self.assertEqual(len(security_contract_failures(clean.data)), 1)
                polluted = revoke_five_contexts(revoker_fixture(mirrors=(foreign_mirror(MERGE),)), event_name)
                self.assertTrue(any(BUILD_MIRROR_QUERY in call for call in polluted.calls), polluted.calls)
                self.assertEqual(len(security_contract_failures(polluted.data)), 1,
                                 "a foreign Actions mirror without the required external id stopped revocation "
                                 "before the Security contract tombstone")
                self.assertTrue(any(check["id"] == 113139755293 for check in
                                    polluted.data[f"repos/{REPOSITORY}/commits/{MERGE}/check-runs"]["check_runs"]))

    def test_manual_revocation_survives_same_parent_tree_merge_regeneration(self) -> None:
        prefix = f"repos/{REPOSITORY}"
        control = revoker_fixture()
        control[f"{prefix}/actions/runs/902/attempts/1"] = revoker_run(902, "workflow_dispatch")
        bound = bind_manual_revocation(control)
        self.assertEqual(bound.result.returncode, 0, bound.result.stderr)
        self.assertIn("eligible=true\n", bound.output)
        regenerated = revoker_fixture(live_merge=REGENERATED_MERGE)
        regenerated[f"{prefix}/actions/runs/902/attempts/1"] = revoker_run(902, "workflow_dispatch")
        run = bind_manual_revocation(regenerated)
        self.assertIn(f"GET {prefix}/git/ref/pull/{PR}/merge", run.calls)
        self.assertEqual(run.result.returncode, 0,
                         "manual revocation of the recorded authority failed once the test merge was regenerated "
                         "with the same parents and tree")
        self.assertIn("eligible=true\n", run.output)
        self.assertIn(f"evidence_sha={EVIDENCE}\n", run.output)

    def test_failed_ci_rerun_after_merge_regeneration_still_records_a_tombstone(self) -> None:
        first = pull_request_ci_run(CI_RUN, MERGE)
        rerun = pull_request_ci_run(CI_RUN, MERGE, conclusion="failure", attempt=2)
        jobs = failed_builder_jobs(CI_RUN)
        control = bind_failed_ci(failed_ci_listener_fixture(rerun, jobs, earlier_attempts=(first,)), rerun)
        self.assertEqual(control.result.returncode, 0, control.result.stderr)
        self.assertIn("eligible=true\n", control.output)
        self.assertIn("create_missing=true\n", control.output)
        run = bind_failed_ci(failed_ci_listener_fixture(rerun, jobs, live_merge=REGENERATED_MERGE,
                                                        earlier_attempts=(first,)), rerun)
        self.assertEqual(run.result.returncode, 0, run.result.stderr)
        self.assertIn(f"GET repos/{REPOSITORY}/git/ref/pull/{PR}/merge", run.calls)
        self.assertIn("eligible=true\n", run.output,
                      "an authenticated failed CI rerun for the committed evidence head recorded no tombstone "
                      "after the test merge was regenerated with the same parents and tree")
        self.assertIn("create_missing=true\n", run.output)
        self.assertIn(f"evidence_sha={EVIDENCE}\n", run.output)


def run_logged_audit(data: dict) -> tuple[OfflineRun, dict]:
    audit = workflow("admin-override-audit.yml")["jobs"]["audit"]
    body = next(step["run"] for step in audit["steps"] if "run" in step)
    script = ROOT / "scripts/audit-security-merge-qualification.py"
    run = run_offline_step(body, data, {
        "CHECK_SHA": PROTECTED, "PR_NUMBER": str(PR), "SECURITY_APP_ID": str(APP_ID),
        "SECURITY_DEFINITION_SHA": DEFINITION, "AUDIT_WORKFLOW_SHA": PROTECTED,
        "GH_TOKEN": "offline-fixture-token", "PYTHONDONTWRITEBYTECODE": "1",
    }, files={f"authorized-auditor/scripts/{script.name}": script.read_bytes()}, collect=("audit.json",))
    return run, json.loads(run.collected.get("audit.json", "{}"))


def with_failed_ci_run(run_id: int, display_title: str, title_base: str = BASE, title_merge: str = MERGE) -> dict:
    data = snapshot()
    prefix = f"repos/{REPOSITORY}"
    failed = copy.deepcopy(data[f"{prefix}/actions/runs/{CI_RUN}"])
    failed.update(id=run_id, display_title=display_title, conclusion="failure", check_suite_id=2 * run_id)
    listing = data[f"{prefix}/actions/runs"]
    listing["workflow_runs"].append(failed)
    listing["total_count"] += 1
    data[f"{prefix}/actions/runs/{run_id}"] = copy.deepcopy(failed)
    data[f"{prefix}/actions/runs/{run_id}/attempts/1"] = copy.deepcopy(failed)
    data[f"{prefix}/actions/runs/{run_id}/attempts/1/jobs"] = {"total_count": 1, "jobs": [
        {"id": 2 * run_id + 1, "name": "Build, lint, test", "run_id": run_id, "head_sha": EVIDENCE,
         "status": "completed", "conclusion": "failure"}]}
    if title_merge != MERGE:
        data[f"{prefix}/git/commits/{title_merge}"] = {
            "sha": title_merge, "parents": [{"sha": title_base}, {"sha": EVIDENCE}], "tree": {"sha": TREE}}
        data[f"{prefix}/commits/{title_merge}/check-runs"] = {"total_count": 0, "check_runs": []}
        data[f"{prefix}/contents/.github/workflows/ci.yml?ref={title_merge}"] = {"sha": "3" * 40}
    return data


class AuditEvidenceHeadOriginalRedTests(unittest.TestCase):
    def test_a_reopened_qualification_cannot_hide_failed_ci_for_the_same_evidence(self) -> None:
        discovery = f"GET repos/{REPOSITORY}/actions/runs?event=pull_request&head_sha={EVIDENCE}&per_page=100&page=1"
        healthy, healthy_report = run_logged_audit(snapshot())
        self.assertEqual(healthy_report.get("status"), "verified", healthy.result.stdout + healthy.result.stderr)
        same, same_report = run_logged_audit(with_failed_ci_run(
            PRIOR_CI_RUN, f"CI N={PR} E={EVIDENCE} B={BASE} M={MERGE}"))
        self.assertEqual(same_report.get("status"), "unverified")
        self.assertNotIn("GitHub read failed", same_report.get("error", ""))
        run, report = run_logged_audit(with_failed_ci_run(
            PRIOR_CI_RUN, f"CI N={PR} E={EVIDENCE} B={BASE} M={PRIOR_MERGE}", title_merge=PRIOR_MERGE))
        self.assertIn(discovery, run.calls)
        self.assertEqual(report.get("status"), "unverified",
                         f"a qualification on a new test merge hid failed CI run {PRIOR_CI_RUN} for the same evidence head")
        self.assertNotIn("GitHub read failed", report.get("error", ""))
        self.assertNotEqual(run.result.returncode, 0)


if __name__ == "__main__":
    unittest.main()

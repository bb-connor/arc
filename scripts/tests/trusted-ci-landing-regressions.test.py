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
import unittest
import zipfile
from pathlib import Path


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
    return data


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
                                                      "EVENT_RUN_ATTEMPT": "2", "EVENT_CONCLUSION": "failure"})
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
                                                              "GITHUB_REPOSITORY": REPOSITORY, "EVENT_WORKFLOW_ID": str(event_id)})
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
    def bind(self, mutation: str = '', conclusion: str | None = 'failure', workflow_state: str = 'active') -> tuple[subprocess.CompletedProcess, str]:
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


class DisabledCriticalCiBinderTests(unittest.TestCase):
    def test_disabled_ci_still_binds_exact_bad_attempt_to_existing_authority(self) -> None:
        body = next(step['run'] for step in workflow('security-contract-revocation.yml')['jobs']['bind-revocation']['steps']
                    if step.get('name') == 'Bind later failed CI rerun to existing authority')
        for state in ('active', 'disabled_manually', 'disabled_inactivity', 'disabled_fork'):
            with self.subTest(state=state):
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
                                        'REPOSITORY_ID': '42', 'REPOSITORY_OWNER_ID': '1', 'GH_TOKEN': 'offline-fixture-only'}
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


if __name__ == "__main__":
    unittest.main()

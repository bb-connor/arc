#!/usr/bin/env python3
"""Authenticate recorded security qualification and retained protected ancestry."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path


class AuditError(RuntimeError):
    pass


SHA = re.compile(r"[0-9a-f]{40}")
CI_TITLE = re.compile(r"CI N=([1-9][0-9]*) E=([0-9a-f]{40}) B=([0-9a-f]{40}) M=([0-9a-f]{40})")
ORDINARY = (
    ("Build, lint, test", "build"),
    ("MSRV build and test", "msrv"),
    ("cargo-vet (locked supply-chain audit)", "vet"),
    ("cargo-deny (supply-chain bans/advisories/licenses)", "deny"),
)
FINALIZER_JOBS = (
    "validate unsigned enterprise Linux capture",
    "sign committed enterprise Linux migration evidence",
    "authorize dedicated Security contract publication",
    "reconcile exact merge authority contexts",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AuditError(message)


def sha(value: object) -> str:
    require(isinstance(value, str) and SHA.fullmatch(value) is not None, "invalid commit or blob SHA")
    return str(value)


def positive_id(value: object) -> int:
    require(isinstance(value, (int, str)) and not isinstance(value, bool)
            and re.fullmatch(r"[1-9][0-9]*", str(value)) is not None, "invalid API identity")
    return int(value)


def unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        require(key not in result, "duplicate authoritative JSON member")
        result[key] = value
    return result


def timestamp(value: object) -> datetime.datetime:
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None,
            "missing immutable completion timestamp")
    return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


class GitHub:
    def __init__(self, repository: str):
        self.prefix = f"repos/{repository}"

    def get(self, path: str) -> dict:
        result = subprocess.run(
            ["gh", "api", "--hostname", "github.com", "--method", "GET",
             "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10",
             self.prefix + ("/" + path if path else "")],
            capture_output=True, check=False, timeout=30,
        )
        require(result.returncode == 0, f"GitHub read failed: {path.split('?')[0]}")
        require(len(result.stdout) <= 16 * 1024 * 1024, "oversized GitHub response")
        response = json.loads(result.stdout, object_pairs_hook=unique_object)
        require(isinstance(response, dict), "GitHub response is not an object")
        return response

    def pages(self, path: str, key: str) -> list[dict]:
        records: list[dict] = []
        total = None
        for page in range(1, 11):
            separator = "&" if "?" in path else "?"
            response = self.get(f"{path}{separator}per_page=100&page={page}")
            count = response.get("total_count")
            require(type(count) is int and 0 <= count < 1000, "unbounded or truncated GitHub inventory")
            if total is None:
                total = count
            require(count == total, "GitHub inventory changed during pagination")
            batch = response.get(key)
            require(isinstance(batch, list) and len(batch) <= 100 and all(isinstance(item, dict) for item in batch),
                    "invalid GitHub inventory page")
            records.extend(batch)
            require(len(records) <= count, "GitHub inventory exceeds its count")
            if len(records) == count:
                identities = [positive_id(item.get("id")) for item in records]
                require(len(set(identities)) == len(identities), "duplicate GitHub inventory identity")
                return records
            require(len(batch) == 100, "incomplete GitHub inventory page")
        raise AuditError("incomplete GitHub inventory")


def workflow_blob(api: GitHub, path: str, ref: str) -> str:
    return sha(api.get(f"contents/{path}?ref={sha(ref)}").get("sha"))


def require_attempt(run: dict, identifier: int, attempt: int, workflow_id: int,
                    path: str, title: str | None, head: str, repository: str, repository_id: int,
                    *, successful: bool = True) -> None:
    require(positive_id(run.get("id")) == identifier and positive_id(run.get("run_attempt")) == attempt,
            "historical run/attempt identity mismatch")
    require(positive_id(run.get("workflow_id")) == workflow_id and run.get("path") == path
            and (title is None or run.get("display_title") == title) and run.get("head_sha") == head,
            "historical workflow, title or source mismatch")
    require(run.get("repository", {}).get("full_name") == repository
            and run.get("head_repository", {}).get("full_name") == repository
            and positive_id(run.get("repository", {}).get("id")) == repository_id
            and positive_id(run.get("head_repository", {}).get("id")) == repository_id,
            "historical repository mismatch")
    if successful:
        require(run.get("status") == "completed" and run.get("conclusion") == "success",
                "critical attempt did not complete successfully")


def foreign_head_run(run: dict, path: str, head: str, repository: str, repository_id: int) -> bool:
    head_repository = run.get("head_repository")
    if not isinstance(head_repository, dict) or not isinstance(run.get("repository"), dict):
        return False
    name, identifier = head_repository.get("full_name"), head_repository.get("id")
    return (run.get("path") == path and run.get("event") == "pull_request" and run.get("head_sha") == head
            and type(run.get("workflow_id")) is int and run["workflow_id"] > 0
            and run["repository"].get("full_name") == repository and run["repository"].get("id") == repository_id
            and type(identifier) is int and identifier > 0 and identifier != repository_id
            and isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+", name) is not None
            and name.lower() != repository.lower())


def metadata(check: dict, identity: dict, source_ci: dict, authority: bool) -> dict:
    text = check.get("output", {}).get("text")
    require(isinstance(text, str) and len(text) <= 65536, "missing authoritative check metadata")
    value = json.loads(text, object_pairs_hook=unique_object)
    fields = {"schema", "identity", "source_ci", "publication_binding_digest" if authority else "source_check"}
    require(isinstance(value, dict) and set(value) == fields
            and value.get("schema") == "chio.security-check-authority.v2"
            and value.get("identity") == identity and value.get("source_ci") == source_ci,
            "check metadata does not bind the exact PR/S/E/M/CI tuple")
    return value


def audit_qualification(api: GitHub, repository: str, pr_number: int,
                        app_id: int, definition: str, audit_workflow_sha: str) -> dict:
    require(app_id != 15368, "dedicated authority cannot use the Actions App")
    audit_path = ".github/workflows/admin-override-audit.yml"
    require(workflow_blob(api, audit_path, definition) == workflow_blob(api, audit_path, audit_workflow_sha),
            "running auditor workflow is not the authorized definition")
    raw = Path(__file__).read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    require(workflow_blob(api, "scripts/audit-security-merge-qualification.py", definition) == blob,
            "auditor code is not the authorized definition")

    repository_record = api.get("")
    require(repository_record.get("full_name") == repository and repository_record.get("default_branch") == "main",
            "audited repository identity mismatch")
    repository_id = positive_id(repository_record.get("id"))
    pr = api.get(f"pulls/{pr_number}")
    require(pr.get("number") == pr_number and pr.get("merged") is True and pr.get("state") == "closed",
            "audit requires the explicit merged pull request")
    require(pr.get("head", {}).get("repo", {}).get("full_name") == repository
            and pr.get("base", {}).get("repo", {}).get("full_name") == repository
            and positive_id(pr.get("head", {}).get("repo", {}).get("id")) == repository_id
            and positive_id(pr.get("base", {}).get("repo", {}).get("id")) == repository_id
            and pr.get("base", {}).get("ref") == "main", "merged PR repository or base mismatch")
    evidence, protected = sha(pr["head"]["sha"]), sha(pr.get("merge_commit_sha"))
    merged_at = timestamp(pr.get("merged_at"))
    protected_commit = api.get(f"git/commits/{protected}")
    parents = protected_commit.get("parents")
    require(isinstance(parents, list) and len(parents) == 2 and parents[1].get("sha") == evidence,
            "protected landing did not retain exact E as its second parent")
    base, tree = sha(parents[0].get("sha")), sha(protected_commit.get("tree", {}).get("sha"))
    require(protected_commit.get("sha") == protected, "protected commit identity mismatch")
    main = api.get("git/ref/heads/main")
    require(main.get("ref") == "refs/heads/main" and main.get("object", {}).get("type") == "commit",
            "invalid protected main ref")
    reachable = api.get(f"compare/{protected}...{sha(main['object']['sha'])}")
    require(reachable.get("status") in {"ahead", "identical"} and reachable.get("behind_by") == 0
            and reachable.get("merge_base_commit", {}).get("sha") == protected,
            "protected merge is not retained on main")

    ci_path = ".github/workflows/ci.yml"
    # Repository-wide discovery retains historical runs across workflow rename,
    # deletion and re-registration. The run path/source and recorded App tuple
    # authenticate the qualification, not the current workflow registry.
    run_query = f"actions/runs?event=pull_request&head_sha={evidence}"
    runs = api.pages(run_query, "workflow_runs")
    # Every attempt of every CI run for E, whatever its title, pull request,
    # base or test merge, must have succeeded before any title selects the
    # positive source. A run whose head is another repository is outside
    # this history only when that identity is complete and distinct.
    history: dict[int, tuple] = {}
    for run in runs:
        require(isinstance(run.get("path"), str), "CI history identity for the evidence head is incomplete")
        if run.get("path") != ci_path or foreign_head_run(run, ci_path, evidence, repository, repository_id):
            continue
        require(run.get("event") == "pull_request" and run.get("head_sha") == evidence
                and run.get("repository", {}).get("full_name") == repository
                and run.get("head_repository", {}).get("full_name") == repository
                and positive_id(run.get("repository", {}).get("id")) == repository_id
                and positive_id(run.get("head_repository", {}).get("id")) == repository_id,
                "CI history identity for the evidence head is incomplete")
        run_id, workflow_id = positive_id(run.get("id")), positive_id(run.get("workflow_id"))
        current = api.get(f"actions/runs/{run_id}")
        maximum = positive_id(current.get("run_attempt"))
        require(maximum <= 100, "unbounded CI attempt history")
        require_attempt(current, run_id, maximum, workflow_id, ci_path, None, evidence, repository, repository_id,
                        successful=False)
        history[run_id] = (maximum, current.get("status"), current.get("conclusion"))
        for attempt in range(1, maximum + 1):
            exact = api.get(f"actions/runs/{run_id}/attempts/{attempt}")
            require_attempt(exact, run_id, attempt, workflow_id, ci_path, None, evidence, repository, repository_id,
                            successful=False)
            require(exact.get("event") == "pull_request", "CI historical event mismatch")
            require(exact.get("status") == "completed" and exact.get("conclusion") == "success",
                    "CI history for the evidence head contains an incomplete or unsuccessful attempt")
    candidates: dict[str, list[dict]] = {}
    for run in runs:
        title = CI_TITLE.fullmatch(str(run.get("display_title", "")))
        if title and title.group(1, 2, 3) == (str(pr_number), evidence, base):
            require(positive_id(run.get("workflow_id")) > 0 and run.get("path") == ci_path
                    and run.get("event") == "pull_request" and run.get("head_sha") == evidence
                    and run.get("head_repository", {}).get("full_name") == repository
                    and positive_id(run.get("head_repository", {}).get("id")) == repository_id
                    and positive_id(run.get("repository", {}).get("id")) == repository_id,
                    "CI discovery tuple is not authenticated by its run identity")
            candidates.setdefault(title.group(4), []).append(run)

    qualified: list[dict] = []
    for merge, matching_runs in candidates.items():
        checks = api.pages(f"commits/{merge}/check-runs?filter=all", "check_runs")
        dedicated = [check for check in checks if check.get("name") == "Security contract"
                     and check.get("app", {}).get("id") == app_id]
        if not dedicated:
            continue
        require(len(dedicated) == 1, "duplicate dedicated authority namespace")
        authority = dedicated[0]
        pattern = re.fullmatch(r"arc:([1-9][0-9]*):([0-9a-f]{40}):([0-9a-f]{40}):([0-9a-f]{40})",
                               str(authority.get("external_id", "")))
        require(pattern is not None and pattern.group(1, 2, 3) == (str(pr_number), evidence, merge),
                "dedicated authority external ID mismatch")
        source = sha(pattern.group(4))
        require(source != evidence, "source and evidence authority are not distinct")
        external_id = f"arc:{pr_number}:{evidence}:{merge}:{source}"
        identity = {"pr_number": str(pr_number), "authorized_source_sha": source,
                    "evidence_sha": evidence, "merge_commit_sha": merge}
        text = json.loads(authority.get("output", {}).get("text", ""), object_pairs_hook=unique_object)
        source_ci = text.get("source_ci") if isinstance(text, dict) else None
        require(isinstance(source_ci, dict) and set(source_ci) == {"run_id", "run_attempt", "workflow_id"},
                "missing exact source CI identity")
        ci_run_id, ci_attempt = positive_id(source_ci["run_id"]), positive_id(source_ci["run_attempt"])
        ci_workflow_id = positive_id(source_ci["workflow_id"])
        require(all(isinstance(value, str) for value in source_ci.values()), "source CI identity mismatch")
        require(sum(run.get("id") == ci_run_id for run in matching_runs) == 1, "source CI is absent from the exact tuple")
        merge_commit = api.get(f"git/commits/{merge}")
        require(merge_commit.get("sha") == merge
                and [parent.get("sha") for parent in merge_commit.get("parents", [])] == [base, evidence]
                and merge_commit.get("tree", {}).get("sha") == tree,
                "qualified test merge parents/tree do not match retained protected landing")
        ancestry = api.get(f"compare/{source}...{evidence}")
        require(ancestry.get("status") == "ahead" and ancestry.get("behind_by") == 0
                and ancestry.get("merge_base_commit", {}).get("sha") == source, "E does not retain authorized source S")
        source_blob = workflow_blob(api, ci_path, source)
        require(source_blob == workflow_blob(api, ci_path, evidence) == workflow_blob(api, ci_path, merge),
                "source CI definition differs at S, E or M")

        title = f"CI N={pr_number} E={evidence} B={base} M={merge}"
        fingerprints: dict[int, tuple] = {}
        for listed in matching_runs:
            run_id = positive_id(listed.get("id"))
            current = api.get(f"actions/runs/{run_id}")
            historical_workflow_id = positive_id(listed.get("workflow_id"))
            maximum = positive_id(current.get("run_attempt"))
            require(maximum <= 100, "unbounded CI attempt history")
            require_attempt(current, run_id, maximum, historical_workflow_id, ci_path, title, evidence, repository, repository_id)
            fingerprints[run_id] = (maximum, current.get("status"), current.get("conclusion"))
            for attempt in range(1, maximum + 1):
                exact = api.get(f"actions/runs/{run_id}/attempts/{attempt}")
                require_attempt(exact, run_id, attempt, historical_workflow_id, ci_path, title, evidence, repository, repository_id)
                require(exact.get("event") == "pull_request", "CI historical event mismatch")
        ci = api.get(f"actions/runs/{ci_run_id}/attempts/{ci_attempt}")
        require_attempt(ci, ci_run_id, ci_attempt, ci_workflow_id, ci_path, title, evidence, repository, repository_id)
        check_suite_id = positive_id(ci.get("check_suite_id"))
        ci_jobs = api.pages(f"actions/runs/{ci_run_id}/attempts/{ci_attempt}/jobs?filter=all", "jobs")
        authority_ids: list[int] = []
        for name, suffix in (*ORDINARY, ("Security contract", "")):
            dedicated_check = not suffix
            context, producer = (name, app_id) if dedicated_check else (f"Security mirror / {name}", 15368)
            namespace = [check for check in checks if check.get("name") == context and check.get("app", {}).get("id") == producer]
            require(len(namespace) == 1, f"missing or duplicate authority namespace: {context}")
            check = namespace[0]
            require(check.get("app", {}).get("slug") == ("chio-security-authority" if dedicated_check else "github-actions")
                    and check.get("head_sha") == merge and check.get("status") == "completed"
                    and check.get("conclusion") == "success"
                    and check.get("external_id") == external_id + (f":actions:{suffix}" if suffix else ""),
                    f"unauthenticated or non-success authority: {context}")
            require(timestamp(check.get("completed_at")) <= merged_at, "authority was published after the protected merge")
            payload = metadata(check, identity, source_ci, dedicated_check)
            authority_ids.append(positive_id(check.get("id")))
            if dedicated_check:
                require(isinstance(payload["publication_binding_digest"], str)
                        and re.fullmatch(r"[0-9a-f]{64}", payload["publication_binding_digest"]) is not None,
                        "missing sealed publication source digest")
                continue
            source_check = payload["source_check"]
            require(isinstance(source_check, dict) and set(source_check) == {"name", "check_run_id"}
                    and source_check.get("name") == name, "mirror source check metadata mismatch")
            identifier = positive_id(source_check.get("check_run_id"))
            original = api.get(f"check-runs/{identifier}")
            require(original.get("id") == identifier and original.get("name") == name
                    and original.get("head_sha") == evidence and original.get("status") == "completed"
                    and original.get("conclusion") == "success"
                    and original.get("app", {}).get("id") == 15368
                    and original.get("app", {}).get("slug") == "github-actions"
                    and positive_id(original.get("check_suite", {}).get("id")) == check_suite_id
                    and original.get("check_suite", {}).get("head_sha") == evidence,
                    "mirror original check is not the exact source CI")
            matching_jobs = [job for job in ci_jobs if job.get("name") == name]
            require(len(matching_jobs) == 1, "source CI job is missing or duplicated")
            original_job = matching_jobs[0]
            require(original_job.get("run_id") == ci_run_id and original_job.get("head_sha") == evidence
                    and original_job.get("status") == "completed" and original_job.get("conclusion") == "success"
                    and original_job.get("check_run_url") == f"https://api.github.com/repos/{repository}/check-runs/{identifier}",
                    "mirror source job does not bind the exact CI attempt")

        details = re.fullmatch(re.escape(f"https://github.com/{repository}/actions/runs/") + r"([1-9][0-9]*)/attempts/([1-9][0-9]*)",
                               str(authority.get("details_url", "")))
        require(details is not None, "dedicated authority lacks an exact finalizer run/attempt")
        finalizer_id, finalizer_attempt = int(details.group(1)), int(details.group(2))
        require(finalizer_attempt == 1, "positive finalizer authority must be first-attempt-only")
        finalizer = api.get(f"actions/runs/{finalizer_id}/attempts/{finalizer_attempt}")
        finalizer_path = ".github/workflows/enterprise-evidence-finalizer.yml"
        finalizer_workflow_id = positive_id(finalizer.get("workflow_id"))
        finalizer_title = str(finalizer.get("display_title", ""))
        require(re.fullmatch(re.escape(f"Enterprise evidence finalizer N={pr_number} E={evidence} M={merge} S={source} K=")
                             + r"[0-9a-f]{64}", finalizer_title) is not None, "finalizer does not bind the exact qualification")
        finalizer_head = sha(finalizer.get("head_sha"))
        require_attempt(finalizer, finalizer_id, finalizer_attempt, finalizer_workflow_id,
                        finalizer_path, finalizer_title, finalizer_head, repository, repository_id)
        require(finalizer.get("event") == "workflow_dispatch" and finalizer.get("head_branch") == "main"
                and finalizer.get("actor", {}).get("login") == "github-actions[bot]"
                and finalizer.get("triggering_actor", {}).get("login") == "github-actions[bot]",
                "finalizer is not the trusted main bot dispatch")
        require(workflow_blob(api, finalizer_path, finalizer_head) == workflow_blob(api, finalizer_path, definition),
                "historical finalizer is not the authorized trusted definition")
        require(timestamp(finalizer.get("updated_at")) <= merged_at, "finalizer completed after protected merge")
        finalizer_jobs = api.pages(f"actions/runs/{finalizer_id}/attempts/{finalizer_attempt}/jobs?filter=all", "jobs")
        require(len(finalizer_jobs) == 4 and {job.get("name") for job in finalizer_jobs} == set(FINALIZER_JOBS),
                "historical finalizer job inventory mismatch")
        require(all(job.get("run_id") == finalizer_id and job.get("head_sha") == finalizer_head
                    and job.get("status") == "completed" and job.get("conclusion") == "success"
                    for job in finalizer_jobs), "historical finalizer did not complete every protected prerequisite")
        # Only the App-authenticated authorizing run owns this authority. A
        # same-title sibling has no binding to it and cannot withdraw it.
        current_finalizer = api.get(f"actions/runs/{finalizer_id}")
        maximum = positive_id(current_finalizer.get("run_attempt"))
        require(maximum <= 100, "unbounded finalizer attempt history")
        require_attempt(current_finalizer, finalizer_id, maximum, finalizer_workflow_id,
                        finalizer_path, finalizer_title, finalizer_head, repository, repository_id)
        finalizer_fingerprint = current_finalizer
        finalizer_attempts = []
        for attempt in range(1, maximum + 1):
            exact = api.get(f"actions/runs/{finalizer_id}/attempts/{attempt}")
            require_attempt(exact, finalizer_id, attempt, finalizer_workflow_id,
                            finalizer_path, finalizer_title, finalizer_head, repository, repository_id,
                            successful=False)
            require(exact.get("event") == "workflow_dispatch" and exact.get("head_branch") == "main"
                    and exact.get("actor", {}).get("login") == "github-actions[bot]",
                    "finalizer history is not the authenticated authorizing run")
            require(exact.get("status") == "completed" and exact.get("conclusion") == "success",
                    "authorizing finalizer history contains an incomplete or sticky bad attempt")
            finalizer_attempts.append({"run_attempt": attempt, "status": exact["status"],
                                       "conclusion": exact["conclusion"]})
        require(api.pages(f"commits/{merge}/check-runs?filter=all", "check_runs") == checks,
                "authority changed during audit")
        for run_id, fingerprint in fingerprints.items():
            current = api.get(f"actions/runs/{run_id}")
            require((current.get("run_attempt"), current.get("status"), current.get("conclusion")) == fingerprint,
                    "CI attempt advanced during audit")
        require(api.get(f"actions/runs/{finalizer_id}") == finalizer_fingerprint,
                "authorizing finalizer changed during audit")
        qualified.append({"pr_number": pr_number, "authorized_source_sha": source, "evidence_sha": evidence,
                          "base_sha": base, "merge_commit_sha": merge, "merge_tree_sha": tree,
                          "source_ci": source_ci, "finalizer": {"run_id": finalizer_id, "run_attempt": finalizer_attempt,
                                                                   "attempts": finalizer_attempts},
                          "authority_check_run_ids": authority_ids})
    require(len(qualified) == 1, "no unique authenticated qualification for this protected landing")
    require(api.pages(run_query, "workflow_runs") == runs, "CI run inventory changed during audit")
    for run_id, fingerprint in history.items():
        current = api.get(f"actions/runs/{run_id}")
        require((current.get("run_attempt"), current.get("status"), current.get("conclusion")) == fingerprint,
                "CI attempt advanced during audit")
    final_pr = api.get(f"pulls/{pr_number}")
    require(final_pr.get("merged") is True and final_pr.get("merge_commit_sha") == protected
            and final_pr.get("head", {}).get("sha") == evidence and final_pr.get("merged_at") == pr.get("merged_at"),
            "merged PR identity changed during audit")
    final_main = api.get("git/ref/heads/main")
    require(final_main.get("ref") == "refs/heads/main" and final_main.get("object", {}).get("type") == "commit",
            "invalid final protected main ref")
    final_main_sha = sha(final_main["object"]["sha"])
    final_reachable = api.get(f"compare/{protected}...{final_main_sha}")
    require(final_reachable.get("status") in {"ahead", "identical"} and final_reachable.get("behind_by") == 0
            and final_reachable.get("merge_base_commit", {}).get("sha") == protected,
            "protected merge was withdrawn from main at the final audit boundary")
    return {"status": "verified", "repository": repository, "qualification": qualified[0],
            "protected_merge_commit_sha": protected, "protected_parents": [base, evidence],
            "protected_tree_sha": tree, "auditor_definition_sha": definition, "observed_main_sha": final_main_sha}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", required=True)
    parser.add_argument("--security-app-id", required=True)
    parser.add_argument("--definition-sha", required=True)
    parser.add_argument("--audit-workflow-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", args.repository) is not None,
                "invalid repository identity")
        result = audit_qualification(GitHub(args.repository), args.repository, positive_id(args.pr_number),
                                    positive_id(args.security_app_id), sha(args.definition_sha), sha(args.audit_workflow_sha))
    except (AuditError, AttributeError, KeyError, TypeError, ValueError, OSError, subprocess.TimeoutExpired) as error:
        result = {"status": "unverified", "repository": args.repository, "pr_number": args.pr_number,
                  "error": str(error), "bypass_attribution": "unestablished"}
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    markdown = "## Protected landing qualification audit\n\n"
    if result["status"] == "verified":
        qualification = result["qualification"]
        markdown += (f"Verified recorded qualification on `{qualification['merge_commit_sha']}` for PR {qualification['pr_number']}.\n\n"
                     f"Main retained merge `{result['protected_merge_commit_sha']}` with ordered parents "
                     f"`{qualification['base_sha']}`, `{qualification['evidence_sha']}` and the qualified tree.\n\n"
                     f"Authorized source: `{qualification['authorized_source_sha']}`. Five authentic authority checks passed.\n")
    else:
        markdown += (f"Recorded protected landing remains unverified: {result['error']}.\n\n"
                     "Administrator bypass attribution is unestablished. Investigate the recorded tuple and external ruleset evidence.\n")
    args.markdown.write_text(markdown, encoding="utf-8")
    print(f"Protected landing qualification: {result['status']}")
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())

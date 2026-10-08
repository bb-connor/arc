#!/usr/bin/env python3
"""Authenticate recorded security qualification and retained protected ancestry."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import io
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time
import zipfile
import zlib
from pathlib import Path


class AuditError(RuntimeError):
    pass


SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"[0-9a-f]{64}")
API_LIMIT = 16 * 1024 * 1024
BINDING_LIMIT = 64 * 1024
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


def invalid_constant(value: str) -> None:
    raise AuditError("non-JSON authoritative constant")


def timestamp(value: object) -> datetime.datetime:
    require(isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value) is not None,
            "missing immutable completion timestamp")
    return datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))


class GitHub:
    def __init__(self, repository: str):
        self.prefix = f"repos/{repository}"

    def binary(self, path: str) -> bytes:
        command = ["gh", "api", "--hostname", "github.com", "--method", "GET",
                   "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2026-03-10",
                   self.prefix + ("/" + path if path else "")]
        # Read incrementally so the download limit bounds memory before parsing.
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
            require(process.stdout is not None and process.stderr is not None, "missing GitHub response streams")
            deadline = time.monotonic() + 30
            output, errors = bytearray(), bytearray()
            try:
                with selectors.DefaultSelector() as pending:
                    pending.register(process.stdout, selectors.EVENT_READ, (output, API_LIMIT))
                    pending.register(process.stderr, selectors.EVENT_READ, (errors, BINDING_LIMIT))
                    while pending.get_map():
                        remaining = deadline - time.monotonic()
                        require(remaining > 0, "GitHub read timed out")
                        ready = pending.select(remaining)
                        require(bool(ready), "GitHub read timed out")
                        for key, _ in ready:
                            target, limit = key.data
                            chunk = os.read(key.fileobj.fileno(), min(65536, limit + 1 - len(target)))
                            if not chunk:
                                pending.unregister(key.fileobj)
                                continue
                            target.extend(chunk)
                            require(len(target) <= limit, "oversized GitHub response")
                remaining = deadline - time.monotonic()
                require(remaining > 0, "GitHub read timed out")
                require(process.wait(timeout=remaining) == 0, f"GitHub read failed: {path.split('?')[0]}")
            except BaseException:
                process.kill()
                process.wait(timeout=5)
                raise
        return bytes(output)

    def get(self, path: str) -> dict:
        response = json.loads(self.binary(path), object_pairs_hook=unique_object, parse_constant=invalid_constant)
        require(isinstance(response, dict), "GitHub response is not an object")
        return response

    def associated_pulls(self, commit: str) -> list[dict]:
        records: list[dict] = []
        for page in range(1, 11):
            raw = self.binary(f"commits/{sha(commit)}/pulls?per_page=100&page={page}")
            batch = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
            require(isinstance(batch, list) and len(batch) <= 100 and all(isinstance(item, dict) for item in batch),
                    "invalid protected landing pull-request page")
            records.extend(batch)
            require(len(records) < 1000, "unbounded protected landing pull-request inventory")
            if len(batch) < 100:
                numbers = [positive_id(item.get("number")) for item in records]
                require(len(set(numbers)) == len(numbers), "duplicate protected landing pull-request identity")
                return records
        raise AuditError("incomplete protected landing pull-request inventory")

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


def digest(value: object) -> str:
    require(isinstance(value, str) and DIGEST.fullmatch(value) is not None, "invalid authoritative SHA-256 digest")
    return str(value)


def string_id(value: object) -> str:
    require(isinstance(value, str) and value.isascii(), "API binding identity must be an ASCII string")
    positive_id(value)
    return str(value)


def metadata(check: dict) -> dict:
    text = check.get("output", {}).get("text")
    require(isinstance(text, str) and len(text.encode("utf-8")) <= BINDING_LIMIT,
            "missing authoritative check metadata")
    value = json.loads(text, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    fields = {"schema", "identity", "identity_digest", "merge_observations", "source_ci",
              "required_check_run_ids", "aggregate_check_run_id", "ci_merge_binding", "publication_binding_digest"}
    require(isinstance(value, dict) and set(value) == fields
            and value.get("schema") == "chio.security-check-authority.v3", "invalid v3 authority metadata")
    identity = value["identity"]
    require(isinstance(identity, dict) and set(identity) == {
                "schema", "repository", "repository_id", "pr_number", "base_sha", "evidence_sha",
                "merge_tree_sha", "authorized_source_sha", "security_definition_sha"}
            and all(isinstance(item, str) and item.isascii() for item in identity.values()),
            "candidate identity must contain the exact ASCII string fields")
    canonical = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii")
    require(digest(value["identity_digest"]) == hashlib.sha256(canonical).hexdigest(),
            "candidate identity digest mismatch")
    observations = value["merge_observations"]
    require(isinstance(observations, dict) and set(observations) == {"capture", "ci"},
            "invalid historical merge observations")
    for item in observations.values():
        sha(item)
    source_ci = value["source_ci"]
    require(isinstance(source_ci, dict) and set(source_ci) == {"run_id", "run_attempt", "workflow_id"},
            "missing exact source CI identity")
    for item in source_ci.values():
        string_id(item)
    required = value["required_check_run_ids"]
    require(isinstance(required, dict) and set(required) == {suffix for _, suffix in ORDINARY},
            "invalid required original check identities")
    identifiers = [string_id(item) for item in required.values()] + [string_id(value["aggregate_check_run_id"])]
    require(len(set(identifiers)) == 5, "duplicate required original check identity")
    binding = value["ci_merge_binding"]
    require(isinstance(binding, dict) and set(binding) == {"artifact_id", "artifact_digest", "binding_sha256"},
            "invalid CI merge-binding artifact identity")
    string_id(binding["artifact_id"])
    digest(binding["artifact_digest"])
    digest(binding["binding_sha256"])
    digest(value["publication_binding_digest"])
    return value


def dedicated_namespace(api: GitHub, evidence: str, app_id: int) -> list[dict]:
    checks = api.pages(f"commits/{evidence}/check-runs?check_name=Security%20contract&app_id={app_id}&filter=all", "check_runs")
    return [check for check in checks if check.get("name") == "Security contract" and check.get("app", {}).get("id") == app_id]


def verify_ci_merge_binding(api: GitHub, repository: str, repository_id: int, pr_number: int,
                            evidence: str, base: str, tree: str, payload: dict) -> None:
    artifact_binding = payload["ci_merge_binding"]
    identifier = positive_id(artifact_binding["artifact_id"])
    source_ci = payload["source_ci"]
    artifact = api.get(f"actions/artifacts/{identifier}")
    require(positive_id(artifact.get("id")) == identifier
            and artifact.get("name") == f"ci-merge-binding-{source_ci['run_id']}-{source_ci['run_attempt']}"
            and artifact.get("expired") is False
            and positive_id(artifact.get("workflow_run", {}).get("id")) == positive_id(source_ci["run_id"])
            and artifact.get("workflow_run", {}).get("head_sha") == evidence
            and artifact.get("digest") == "sha256:" + artifact_binding["artifact_digest"],
            "CI merge-binding artifact provenance mismatch")
    size = artifact.get("size_in_bytes")
    require(type(size) is int and 0 < size <= API_LIMIT, "invalid CI merge-binding archive size")
    archive = api.binary(f"actions/artifacts/{identifier}/zip")
    require(len(archive) == size and hashlib.sha256(archive).hexdigest() == artifact_binding["artifact_digest"],
            "CI merge-binding archive size or digest mismatch")
    with zipfile.ZipFile(io.BytesIO(archive)) as source:
        members = source.infolist()
        names = [member.filename for member in members]
        require(len(set(names)) == len(names), "duplicate CI merge-binding archive member")
        matching = [member for member in members if member.filename == "ci-merge-binding.json"]
        require(len(matching) == 1, "missing or ambiguous CI merge-binding member")
        member = matching[0]
        mode = stat.S_IFMT(member.external_attr >> 16)
        require(not member.is_dir() and not member.external_attr & 0x10
                and mode in {0, stat.S_IFREG} and not member.flag_bits & 1,
                "non-regular CI merge-binding archive member")
        require(0 < member.file_size <= BINDING_LIMIT and 0 < member.compress_size <= len(archive),
                "invalid CI merge-binding member size")
        with source.open(member) as body:
            raw = body.read(BINDING_LIMIT + 1)
        require(len(raw) == member.file_size and len(raw) <= BINDING_LIMIT
                and hashlib.sha256(raw).hexdigest() == artifact_binding["binding_sha256"],
                "CI merge-binding member size or digest mismatch")
    binding = json.loads(raw, object_pairs_hook=unique_object, parse_constant=invalid_constant)
    require(isinstance(binding, dict) and set(binding) == {
                "schema", "repository", "pull_request_number", "head", "base", "merge", "ci", "caller", "builder"}
            and binding.get("schema") == "https://github.com/bb-connor/arc/attestations/ci-merge-binding/v1",
            "invalid authenticated CI merge-binding schema")
    merge = payload["merge_observations"]["ci"]
    require(binding.get("pull_request_number") == str(pr_number)
            and binding.get("repository", {}).get("name") == repository
            and binding.get("repository", {}).get("id") == str(repository_id)
            and binding.get("head", {}).get("repository") == repository
            and binding.get("head", {}).get("repository_id") == str(repository_id)
            and binding.get("head", {}).get("sha") == evidence
            and binding.get("base", {}).get("repository") == repository
            and binding.get("base", {}).get("repository_id") == str(repository_id)
            and binding.get("base", {}).get("ref") == "main" and binding.get("base", {}).get("sha") == base
            and binding.get("merge", {}).get("sha") == merge
            and binding.get("merge", {}).get("parents") == [base, evidence]
            and binding.get("merge", {}).get("tree_sha") == tree
            and binding.get("merge", {}).get("ref") == f"refs/pull/{pr_number}/merge",
            "CI merge-binding does not match the retained landing identity")
    bound_ci = binding.get("ci", {})
    require(all(bound_ci.get(key) == value for key, value in source_ci.items())
            and bound_ci.get("event") == "pull_request"
            and bound_ci.get("run_name") == f"CI N={pr_number} E={evidence} B={base} M={merge}"
            and binding.get("caller", {}).get("definition_sha") == merge
            and binding.get("caller", {}).get("workflow_path") == ".github/workflows/ci.yml"
            and binding.get("caller", {}).get("workflow_ref") == f"{repository}/.github/workflows/ci.yml@refs/pull/{pr_number}/merge"
            and binding.get("builder", {}).get("definition_sha") == payload["identity"]["security_definition_sha"]
            and binding.get("builder", {}).get("workflow_path") == ".github/workflows/enterprise-hardening.yml",
            "CI merge-binding does not match the authenticated source attempt or trusted definition")
    # Sigstore was verified by the App-authenticated historical finalizer.
    # This read authenticates its recorded artifact digests and exact tuple.


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
        latest: tuple = ()
        for attempt in range(1, maximum + 1):
            exact = api.get(f"actions/runs/{run_id}/attempts/{attempt}")
            require_attempt(exact, run_id, attempt, workflow_id, ci_path, None, evidence, repository, repository_id,
                            successful=False)
            require(exact.get("event") == "pull_request", "CI historical event mismatch")
            require(exact.get("status") == "completed" and exact.get("conclusion") == "success",
                    "CI history for the evidence head contains an incomplete or unsuccessful attempt")
            latest = (positive_id(exact.get("run_attempt")), exact.get("status"), exact.get("conclusion"))
        require((run.get("run_attempt"), run.get("status"), run.get("conclusion"))
                == (current.get("run_attempt"), current.get("status"), current.get("conclusion"))
                == latest == (maximum, "completed", "success"),
                "CI history run projection disagrees with its latest successful attempt")
    checks = dedicated_namespace(api, evidence, app_id)
    require(len(checks) == 1, "missing or duplicate dedicated authority namespace on E")
    authority = checks[0]
    require(not str(authority.get("external_id", "")).startswith("arc:"),
            "legacy M-keyed authority is not a v3 qualification")
    payload = metadata(authority)
    identity, identity_digest = payload["identity"], payload["identity_digest"]
    source, security_definition = sha(identity["authorized_source_sha"]), sha(identity["security_definition_sha"])
    require(identity == {"schema": "chio.security-candidate-identity.v1", "repository": repository,
                         "repository_id": str(repository_id), "pr_number": str(pr_number),
                         "base_sha": base, "evidence_sha": evidence, "merge_tree_sha": tree,
                         "authorized_source_sha": source, "security_definition_sha": security_definition},
            "candidate identity does not match the retained protected landing")
    require(source != evidence, "source and evidence authority are not distinct")
    pattern = re.fullmatch(r"chio:v3:([1-9][0-9]*):([0-9a-f]{40}):([0-9a-f]{64})",
                           str(authority.get("external_id", "")))
    require(pattern is not None and pattern.group(1, 2, 3) == (str(pr_number), evidence, identity_digest),
            "dedicated authority external ID mismatch")
    require(authority.get("app", {}).get("slug") == "chio-security-authority"
            and authority.get("head_sha") == evidence and authority.get("status") == "completed"
            and authority.get("conclusion") == "success", "unauthenticated or non-success dedicated authority")
    require(timestamp(authority.get("completed_at")) <= merged_at, "authority was published after the protected merge")
    observations, source_ci = payload["merge_observations"], payload["source_ci"]
    merge = observations["ci"]
    ci_run_id, ci_attempt = positive_id(source_ci["run_id"]), positive_id(source_ci["run_attempt"])
    ci_workflow_id = positive_id(source_ci["workflow_id"])
    matching_runs = []
    for run in runs:
        candidate = CI_TITLE.fullmatch(str(run.get("display_title", "")))
        if candidate and candidate.group(1, 2, 3, 4) == (str(pr_number), evidence, base, merge):
            require(positive_id(run.get("workflow_id")) > 0 and run.get("path") == ci_path
                    and run.get("event") == "pull_request" and run.get("head_sha") == evidence
                    and run.get("head_repository", {}).get("full_name") == repository
                    and positive_id(run.get("head_repository", {}).get("id")) == repository_id
                    and positive_id(run.get("repository", {}).get("id")) == repository_id,
                    "CI discovery tuple is not authenticated by its run identity")
            matching_runs.append(run)
    require(ci_run_id in history and sum(run.get("id") == ci_run_id for run in matching_runs) == 1,
            "source CI is absent from the exact authenticated history tuple")
    merge_commit = api.get(f"git/commits/{merge}")
    require(merge_commit.get("sha") == merge
            and [parent.get("sha") for parent in merge_commit.get("parents", [])] == [base, evidence]
            and merge_commit.get("tree", {}).get("sha") == tree,
            "qualified test merge parents/tree do not match retained protected landing")
    ancestry = api.get(f"compare/{source}...{evidence}")
    require(ancestry.get("status") == "ahead" and ancestry.get("behind_by") == 0
            and ancestry.get("merge_base_commit", {}).get("sha") == source, "E does not retain authorized source S")
    source_blob = workflow_blob(api, ci_path, source)
    require(source_blob == workflow_blob(api, ci_path, evidence) == workflow_blob(api, ci_path, protected),
            "source CI definition differs at S, E or L")

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
    for name, suffix in (*ORDINARY, ("Security contract", "aggregate")):
        matching_jobs = [job for job in ci_jobs if job.get("name") == name]
        require(len(matching_jobs) == 1, "source CI job is missing or duplicated")
        original_job = matching_jobs[0]
        require(original_job.get("run_id") == ci_run_id and original_job.get("head_sha") == evidence
                and original_job.get("status") == "completed" and original_job.get("conclusion") == "success",
                "source job does not bind the exact CI attempt")
        check_url = re.fullmatch(re.escape(f"https://api.github.com/repos/{repository}/check-runs/")
                                + r"([1-9][0-9]*)", str(original_job.get("check_run_url", "")))
        require(check_url is not None, "source job does not bind an exact repository check")
        identifier = int(check_url.group(1))
        bound_identifier = (payload["aggregate_check_run_id"] if suffix == "aggregate"
                            else payload["required_check_run_ids"][suffix])
        require(str(identifier) == bound_identifier, "source CI inventory does not match the sealed original check ID")
        original = api.get(f"check-runs/{identifier}")
        require(original.get("id") == identifier and original.get("name") == name
                and original.get("head_sha") == evidence and original.get("status") == "completed"
                and original.get("conclusion") == "success"
                and original.get("app", {}).get("id") == 15368
                and original.get("app", {}).get("slug") == "github-actions"
                and positive_id(original.get("check_suite", {}).get("id")) == check_suite_id
                and original.get("check_suite", {}).get("head_sha") == evidence,
                "original check is not the exact source CI")

    verify_ci_merge_binding(api, repository, repository_id, pr_number, evidence, base, tree, payload)

    details = re.fullmatch(re.escape(f"https://github.com/{repository}/actions/runs/") + r"([1-9][0-9]*)/attempts/([1-9][0-9]*)",
                           str(authority.get("details_url", "")))
    require(details is not None, "dedicated authority lacks an exact finalizer run/attempt")
    finalizer_id, finalizer_attempt = int(details.group(1)), int(details.group(2))
    require(finalizer_attempt == 1, "positive finalizer authority must be first-attempt-only")
    finalizer = api.get(f"actions/runs/{finalizer_id}/attempts/{finalizer_attempt}")
    finalizer_path = ".github/workflows/enterprise-evidence-finalizer.yml"
    finalizer_workflow_id = positive_id(finalizer.get("workflow_id"))
    finalizer_title = str(finalizer.get("display_title", ""))
    require(re.fullmatch(re.escape(f"Enterprise evidence finalizer N={pr_number} E={evidence} M={observations['capture']} S={source} K=")
                         + r"[0-9a-f]{64}", finalizer_title) is not None, "finalizer does not bind the exact qualification")
    finalizer_head = sha(finalizer.get("head_sha"))
    require_attempt(finalizer, finalizer_id, finalizer_attempt, finalizer_workflow_id,
                    finalizer_path, finalizer_title, finalizer_head, repository, repository_id)
    require(finalizer.get("event") == "workflow_dispatch" and finalizer.get("head_branch") == "main"
            and finalizer.get("actor", {}).get("login") == "github-actions[bot]"
            and finalizer.get("triggering_actor", {}).get("login") == "github-actions[bot]",
            "finalizer is not the trusted main bot dispatch")
    require(workflow_blob(api, finalizer_path, finalizer_head) == workflow_blob(api, finalizer_path, security_definition),
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
    require(dedicated_namespace(api, evidence, app_id) == checks,
            "authority changed during audit")
    for run_id, fingerprint in fingerprints.items():
        current = api.get(f"actions/runs/{run_id}")
        require((current.get("run_attempt"), current.get("status"), current.get("conclusion")) == fingerprint,
                "CI attempt advanced during audit")
    require(api.get(f"actions/runs/{finalizer_id}") == finalizer_fingerprint,
            "authorizing finalizer changed during audit")
    qualification = {"pr_number": pr_number, "authorized_source_sha": source, "evidence_sha": evidence,
                     "base_sha": base, "merge_tree_sha": tree, "identity": identity, "identity_digest": identity_digest,
                     "merge_observations": observations, "source_ci": source_ci,
                     "required_check_run_ids": payload["required_check_run_ids"],
                     "aggregate_check_run_id": payload["aggregate_check_run_id"],
                     "authority_check_run_id": positive_id(authority.get("id")),
                     "finalizer": {"run_id": finalizer_id, "run_attempt": finalizer_attempt, "attempts": finalizer_attempts}}
    require(api.pages(run_query, "workflow_runs") == runs, "CI run inventory changed during audit")
    for run_id, fingerprint in history.items():
        current = api.get(f"actions/runs/{run_id}")
        require((current.get("run_attempt"), current.get("status"), current.get("conclusion")) == fingerprint,
                "CI attempt advanced during audit")
    associated = api.associated_pulls(protected)
    require(any(pull.get("number") == pr_number for pull in associated)
            and not any(pull.get("number") != pr_number and pull.get("merge_commit_sha") == protected for pull in associated),
            "observed protected landing attribution does not uniquely identify the audited PR")
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
    return {"status": "verified", "repository": repository, "qualification": qualification,
            "protected_merge_commit_sha": protected, "protected_parents": [base, evidence],
            "protected_tree_sha": tree, "auditor_definition_sha": definition, "observed_main_sha": final_main_sha,
            "landing_attribution": f"observed commits/{protected}/pulls signal; not enforcement"}


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
    except (AuditError, AttributeError, KeyError, TypeError, ValueError, OSError, subprocess.TimeoutExpired, zipfile.BadZipFile, RuntimeError, NotImplementedError, zlib.error) as error:
        result = {"status": "unverified", "repository": args.repository, "pr_number": args.pr_number,
                  "error": str(error), "bypass_attribution": "unestablished"}
    args.output.write_text(json.dumps(result, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    markdown = "## Protected landing qualification audit\n\n"
    if result["status"] == "verified":
        qualification = result["qualification"]
        markdown += (f"Verified recorded qualification `{qualification['identity_digest']}` on evidence head "
                     f"`{qualification['evidence_sha']}` for PR {qualification['pr_number']}.\n\n"
                     f"Main retained merge `{result['protected_merge_commit_sha']}` with ordered parents "
                     f"`{qualification['base_sha']}`, `{qualification['evidence_sha']}` and the qualified tree.\n\n"
                     f"Authorized source: `{qualification['authorized_source_sha']}`. The dedicated authority check and five original CI checks passed.\n\n"
                     f"Landing attribution: {result['landing_attribution']}.\n")
    else:
        markdown += (f"Recorded protected landing remains unverified: {result['error']}.\n\n"
                     "Administrator bypass attribution is unestablished. Investigate the recorded tuple and external ruleset evidence.\n")
    args.markdown.write_text(markdown, encoding="utf-8")
    print(f"Protected landing qualification: {result['status']}")
    return 0 if result["status"] == "verified" else 1


if __name__ == "__main__":
    raise SystemExit(main())

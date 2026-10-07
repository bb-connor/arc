#!/usr/bin/env python3
"""Validate all isolated refresh shards before publishing one unsigned patch.

Run from the reviewed tooling checkout. Candidate files and downloaded artifacts
are data; only the adjacent reviewed checker and execution modules are imported.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


class AggregationError(RuntimeError):
    pass


TOOL_ROOT = Path(__file__).resolve().parents[1]
MANIFEST = "crates/core/chio-adversarial-suite/manifest.json"


def load_tool(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(
        name, TOOL_ROOT / "scripts" / filename
    )
    if spec is None or spec.loader is None:
        raise AggregationError("reviewed evidence tooling is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ENTRY = load_tool("aggregate_entry", "security-execution-container-entrypoint.py")
HOST = load_tool("aggregate_host", "run-security-execution-container.py")
CHECKER = load_tool("aggregate_checker", "check-security-adversarial-evidence.py")


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def validate_inventory(value: dict, index: int, source: str, patch: bytes) -> None:
    campaigns, paths = ENTRY.refresh_shard(index)
    expected = {
        "schema": "chio.security-evidence-refresh-shard.v1",
        "shard": index,
        "shard_count": ENTRY.REFRESH_SHARD_COUNT,
        "source_sha": source,
        "campaigns": list(campaigns),
        "paths": list(paths),
        "campaign_count": len(campaigns),
        "outcome_count": len(campaigns),
        "case_count": len(paths) - len(campaigns) - 1,
        "patch_sha256": hashlib.sha256(patch).hexdigest(),
    }
    if not isinstance(value, dict) or set(value) != {*expected, "execution_boundary"}:
        raise AggregationError("partial evidence inventory fields are not exact")
    if any(
        type(value[key]) is not type(want) or value[key] != want
        for key, want in expected.items()
    ):
        raise AggregationError(
            "partial evidence source, shard, paths or checksum changed"
        )
    boundary = value["execution_boundary"]
    if not isinstance(boundary, dict) or set(boundary) != {
        "schema",
        "image_id",
        "platform",
        "seccomp_profile_sha256",
        "trusted_file_sha256",
    }:
        raise AggregationError("partial evidence execution boundary fields changed")
    hashes = boundary["trusted_file_sha256"]
    if (
        boundary["schema"] != "chio.security-execution-boundary.v1"
        or boundary["platform"] != "linux/amd64"
        or not isinstance(boundary["image_id"], str)
        or not HOST.IMAGE_PATTERN.fullmatch(boundary["image_id"])
        or not isinstance(boundary["seccomp_profile_sha256"], str)
        or not re.fullmatch(r"[a-f0-9]{64}", boundary["seccomp_profile_sha256"])
        or not isinstance(hashes, dict)
        or set(hashes) != HOST.TRUSTED_BOUNDARY_FILE_KEYS
        or any(
            not isinstance(digest, str) or not re.fullmatch(r"[a-f0-9]{64}", digest)
            for digest in hashes.values()
        )
    ):
        raise AggregationError("partial evidence execution identity is invalid")


def shard_directories(root: Path) -> list[Path]:
    expected = {f"shard-{index}" for index in range(ENTRY.REFRESH_SHARD_COUNT)}
    if root.is_symlink() or not root.is_dir() or set(os.listdir(root)) != expected:
        raise AggregationError(
            "aggregation requires exactly the seven shard directories"
        )
    result = [root / f"shard-{index}" for index in range(ENTRY.REFRESH_SHARD_COUNT)]
    if any(not stat.S_ISDIR(path.lstat().st_mode) for path in result):
        raise AggregationError("shard directories must be real directories")
    return result


def validate_case_repair(before: dict, after: dict) -> None:
    if after.get("pending") is not False:
        raise AggregationError("a refreshed case remains pending")
    original, repaired = copy.deepcopy(before), copy.deepcopy(after)
    original.pop("pending", None)
    repaired.pop("pending", None)
    try:
        for campaign in repaired["artifact"]["campaigns"]:
            for key in ("sha256", "inputs_sha256"):
                digest = campaign["outcomes"][key]
                if not isinstance(digest, str) or not re.fullmatch(
                    r"[a-f0-9]{64}", digest
                ):
                    raise AggregationError(
                        "refreshed case lacks an exact outcome binding"
                    )
        for value in (original, repaired):
            for campaign in value["artifact"]["campaigns"]:
                campaign["outcomes"].pop("sha256", None)
                campaign["outcomes"].pop("inputs_sha256", None)
    except (KeyError, TypeError) as error:
        raise AggregationError("refreshed case shape changed") from error
    if original != repaired:
        raise AggregationError(
            "shard changed a case definition outside derived outcome bindings"
        )


def trusted_hashes() -> dict[str, str]:
    paths = {
        name: f"scripts/{name}"
        for name in HOST.TRUSTED_BOUNDARY_FILE_KEYS
        if name != "cargo-mutants"
    }
    paths.update(
        {
            "entrypoint.py": "scripts/security-execution-container-entrypoint.py",
            "command-client.py": "scripts/security-execution-command-client.py",
            "security-evidence-seccomp.json": "deploy/docker/security-evidence-seccomp.json",
            "check-cage-linux-enforcement.sh": "crates/security/chio-cage/scripts/check-linux-enforcement.sh",
            **{
                f"verifier-bin/{name}": "scripts/security-execution-command-client.py"
                for name in ("cargo", "cc", "ldd")
            },
        }
    )
    return {
        name: hashlib.sha256(
            HOST.read_regular_file_once(
                TOOL_ROOT / path,
                HOST.MAX_FILE_BYTES,
                True,
            )
        ).hexdigest()
        for name, path in paths.items()
    }


def load_shards(root: Path, source: str) -> list[tuple[dict, bytes]]:
    expected_hashes = trusted_hashes()
    result = []
    engine_hash = None
    total = 0
    for index, path in enumerate(shard_directories(root)):
        names = HOST.OUTPUT_SPECS["refresh-all-evidence"].names
        if set(os.listdir(path)) != set(names):
            raise AggregationError("shard output file inventory changed")
        payload = {
            name: HOST.read_regular_file_once(path / name, HOST.MAX_FILE_BYTES, True)
            for name in names
        }
        total += sum(map(len, payload.values()))
        if total > HOST.MAX_TOTAL_OUTPUT_BYTES:
            raise AggregationError("shards exceed the aggregate input bound")
        value = CHECKER.parse_json_payload(
            payload["all-evidence-inventory.json"], "shard inventory"
        )
        if canonical(value) != payload["all-evidence-inventory.json"]:
            raise AggregationError("shard inventory is not canonical")
        patch = payload["all-evidence.patch"]
        validate_inventory(value, index, source, patch)
        digest = value["patch_sha256"]
        if (
            payload["source-sha.txt"] != f"{source}\n".encode()
            or payload["all-evidence.patch.sha256"]
            != f"{digest}  all-evidence.patch\n".encode()
        ):
            raise AggregationError("shard sidecar identity changed")
        boundary = value["execution_boundary"]
        hashes = boundary["trusted_file_sha256"]
        if any(hashes[name] != digest for name, digest in expected_hashes.items()):
            raise AggregationError("shard did not use the reviewed tooling bytes")
        if (
            boundary["seccomp_profile_sha256"]
            != expected_hashes["security-evidence-seccomp.json"]
        ):
            raise AggregationError("shard seccomp identity changed")
        if engine_hash is not None and engine_hash != hashes["cargo-mutants"]:
            raise AggregationError("shards disagree on the mutation engine binary")
        engine_hash = hashes["cargo-mutants"]
        result.append((value, patch))
    return result


def git(root: Path, *arguments: str, payload: bytes | None = None) -> bytes:
    # Object identity and callback suppression match the private source reader.
    # Content filters are refused separately before any linked checkout.
    command = [
        "/usr/bin/git",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "-c", "diff.external=",
        "-c", "log.showSignature=false",
        "-C", str(root),
        *arguments,
    ]
    result = subprocess.run(
        command,
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        env=HOST.clean_host_env(),
        check=False,
    )
    if result.returncode:
        raise AggregationError(
            f"evidence Git operation failed: {result.stderr[-4096:]!r}"
        )
    if len(result.stdout) > HOST.MAX_TOTAL_OUTPUT_BYTES:
        raise AggregationError("evidence Git result exceeded its bound")
    return result.stdout


def require_authorized_candidate(root: Path, source: str, authorized: str) -> None:
    """Preserve the controller's maximum 32 signed-evidence-only descendants."""
    if not all(HOST.SHA_PATTERN.fullmatch(value) for value in (source, authorized)):
        raise AggregationError("source authorization requires exact commit identities")
    allowed = {
        str(CHECKER.DERIVED_LINUX_EVIDENCE_ROOT / name).encode()
        for name in CHECKER.DERIVED_LINUX_EVIDENCE_FILES
    }
    cursor = source
    for distance in range(33):
        if cursor == authorized:
            break
        if distance == 32:
            raise AggregationError(
                "candidate exceeds the authorized evidence ancestry bound"
            )
        parents = (
            git(root, "show", "--format=%P", "--no-patch", cursor).decode().split()
        )
        if len(parents) != 1:
            raise AggregationError("evidence descendants must have exactly one parent")
        changes = git(
            root,
            "diff",
            "--name-status",
            "-z",
            "--no-renames",
            parents[0],
            cursor,
            "--",
        ).split(b"\0")
        if changes[-1] != b"" or len(changes) not in (3, 5, 7):
            raise AggregationError("evidence descendant must change one to three files")
        for status, path in zip(changes[:-1:2], changes[1::2], strict=True):
            if status not in (b"A", b"M") or path not in allowed:
                raise AggregationError(
                    "candidate changes unreviewed source or deletes evidence"
                )
            entry = git(root, "ls-tree", "-z", cursor, "--", path.decode())
            if not entry.startswith(b"100644 blob ") or entry.count(b"\0") != 1:
                raise AggregationError(
                    "evidence descendants require regular nonexecutable blobs"
                )
        cursor = parents[0]
    if source != authorized:
        rows = git(
            root, "ls-tree", "-z", f"{source}:{CHECKER.DERIVED_LINUX_EVIDENCE_ROOT}"
        ).split(b"\0")[:-1]
        expected = {name.encode() for name in CHECKER.DERIVED_LINUX_EVIDENCE_FILES}
        if (
            len(rows) != 3
            or any(not row.startswith(b"100644 blob ") for row in rows)
            or {row.split(b"\t", 1)[-1] for row in rows} != expected
        ):
            raise AggregationError("candidate signed evidence directory is not closed")


def apply_shard(root: Path, inventory: dict, patch: bytes) -> None:
    rows = git(root, "apply", "--numstat", "-z", "-", payload=patch).split(b"\0")
    names = []
    for row in filter(None, rows):
        fields = row.split(b"\t", 2)
        if len(fields) != 3 or any(not field.isdigit() for field in fields[:2]):
            raise AggregationError("shard must contain only text evidence patches")
        names.append(fields[2].decode("utf-8"))
    if sorted(names) != inventory["paths"]:
        raise AggregationError("shard patch paths differ from its exact inventory")
    # All cases for a shard are disjoint. Rebuild the shared manifest once below.
    git(root, "apply", "--index", f"--exclude={MANIFEST}", "-", payload=patch)
    for name in inventory["paths"]:
        if name == MANIFEST:
            continue
        entry = git(root, "ls-files", "--stage", "--", name).decode()
        if not entry.startswith("100644 ") or len(entry.splitlines()) != 1:
            raise AggregationError(
                "shard evidence must remain a single regular index entry"
            )
        current = HOST.read_regular_file_once(root / name, HOST.MAX_FILE_BYTES, True)
        if name.startswith("crates/core/chio-adversarial-suite/cases/"):
            before = CHECKER.parse_json_payload(git(root, "show", f"HEAD:{name}"), name)
            after = CHECKER.parse_json_payload(current, name)
            validate_case_repair(before, after)


def rebuild_manifest(root: Path) -> None:
    manifest = CHECKER.load_json(root / MANIFEST)
    entries = {entry["id"]: entry for entry in manifest["cases"]}
    if len(entries) != len(manifest["cases"]) or manifest["case_count"] != len(entries):
        raise AggregationError("source manifest inventory is ambiguous")
    for name in sorted({case for _, _, case in ENTRY.ALL_REFRESH_INVENTORY}):
        path = root / name
        payload = HOST.read_regular_file_once(path, HOST.MAX_FILE_BYTES, True)
        value = CHECKER.parse_json_payload(payload, name)
        entries[value["id"]] = CHECKER.manifest_case_entry(root, path, value, payload)
    manifest["cases"] = [entries[key] for key in sorted(entries)]
    manifest["case_count"] = len(entries)
    (root / MANIFEST).write_bytes(CHECKER.canonical_json_bytes(manifest))
    git(root, "add", "--", MANIFEST)


def validate_composed(root: Path, authorized: str, image: str, temporary: Path) -> dict:
    """Run the complete checker through the same credential-free execution boundary."""
    git(
        root,
        "-c",
        "user.name=Chio evidence aggregation",
        "-c",
        "user.email=chio-evidence@users.noreply.github.com",
        "commit",
        "--no-gpg-sign",
        "-m",
        "test: validate composed unsigned evidence",
    )
    tested_sha = git(root, "rev-parse", "HEAD").decode().strip()
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            str(TOOL_ROOT / "scripts/run-security-execution-container.py"),
            "--authorized-source-sha",
            authorized,
            "--candidate",
            str(root),
            "--expected-sha",
            tested_sha,
            "--image",
            image,
            "--operation",
            "validate-committed-evidence",
            "--output-dir",
            str(temporary / "validated"),
            "--state-dir",
            str(temporary / "execution-state"),
            "--timeout-seconds",
            "600",
        ],
        check=False,
        timeout=660,
    )
    if result.returncode:
        raise AggregationError("complete composed evidence failed isolated validation")
    log = HOST.read_regular_file_once(
        temporary / "validated/committed-adversarial-evidence.log",
        HOST.MAX_FILE_BYTES,
        True,
    )
    return {
        "tested_sha": tested_sha,
        "image_id": image,
        "log_sha256": hashlib.sha256(log).hexdigest(),
        "log": log.decode("utf-8"),
    }


def aggregate(
    candidate: Path,
    source: str,
    shards: Path,
    output: Path,
    image: str,
    *,
    authorized_source: str,
) -> None:
    if not HOST.SHA_PATTERN.fullmatch(source) or not HOST.IMAGE_PATTERN.fullmatch(
        image
    ):
        raise AggregationError("aggregation requires an exact source commit")
    try:
        HOST.repository_identity(candidate, source, None)
    except HOST.BoundaryError as error:
        raise AggregationError(f"candidate source verification failed: {error}") from error
    require_authorized_candidate(candidate, source, authorized_source)
    inputs = load_shards(shards, source)
    with tempfile.TemporaryDirectory(prefix="chio-evidence-aggregation-") as temporary:
        workspace = Path(temporary) / "source"
        git(candidate, "worktree", "add", "--detach", str(workspace), source)
        try:
            for inventory, patch in inputs:
                apply_shard(workspace, inventory, patch)
            rebuild_manifest(workspace)
            changed = (
                git(workspace, "diff", "--cached", "--name-only", "-z")
                .decode()
                .split("\0")[:-1]
            )
            if sorted(changed) != list(ENTRY.ALL_REFRESH_PATHS):
                raise AggregationError(
                    "composed evidence does not change exactly the 64 derived paths"
                )
            patch = git(
                workspace,
                "diff",
                "--cached",
                "--binary",
                "--no-ext-diff",
                "--no-textconv",
                "--no-renames",
            )
            if not patch or len(patch) > HOST.MAX_FILE_BYTES:
                raise AggregationError(
                    "composed evidence patch exceeds its import bound"
                )
            digest = hashlib.sha256(patch).hexdigest()
            validation = validate_composed(
                workspace, authorized_source, image, Path(temporary)
            )
            inventory = {
                "schema": "chio.security-evidence-refresh-aggregate.v1",
                "source_sha": source,
                "authorized_source_sha": authorized_source,
                "campaign_count": 35,
                "outcome_count": 35,
                "case_count": 28,
                "campaigns": list(ENTRY.ALL_CAMPAIGNS),
                "paths": list(ENTRY.ALL_REFRESH_PATHS),
                "patch_sha256": digest,
                "shards": [item for item, _ in inputs],
                "validation": validation,
            }
            HOST.publish_outputs(
                output,
                {
                    "all-evidence-inventory.json": canonical(inventory),
                    "all-evidence.patch": patch,
                    "all-evidence.patch.sha256": f"{digest}  all-evidence.patch\n".encode(),
                    "source-sha.txt": f"{source}\n".encode(),
                },
            )
        finally:
            git(candidate, "worktree", "remove", "--force", str(workspace))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True, type=Path)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--authorized-source-sha", required=True)
    parser.add_argument("--shards", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    aggregate(
        args.candidate.resolve(strict=True),
        args.expected_sha,
        args.shards.absolute(),
        args.output_dir.absolute(),
        args.image,
        authorized_source=args.authorized_source_sha,
    )


if __name__ == "__main__":
    try:
        main()
    except (
        AggregationError,
        HOST.BoundaryError,
        CHECKER.EvidenceError,
        OSError,
        ValueError,
        subprocess.TimeoutExpired,
    ) as error:
        print(f"evidence aggregation failed: {str(error)!r}", file=sys.stderr)
        raise SystemExit(1)

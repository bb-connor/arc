"""Verify a received patch bundle using the reviewer's source and kernel key."""

import json
import os
import re
import stat

from chio_mini_swe.provider_config import reject_constant, unique_object
from chio_mini_swe.repository_archive import MAX_ARCHIVE, canonical, digest, import_revision, patch
from chio_mini_swe.repository_proof import MAX_RECEIPTS, output_digest, verified_receipts
from chio_mini_swe.repository_store import MAX_COMMANDS, configuration_digest
from chio_mini_swe.repository_wire import validate_result


def read_file(path, maximum, *, directory=None):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
            raise ValueError("Review input must be a bounded regular file")
        data = stream.read(maximum + 1)
    if len(data) > maximum:
        raise ValueError("Review input exceeds its byte limit")
    return data


def document(data):
    return json.loads(data, object_pairs_hook=unique_object, parse_constant=reject_constant)


def fields(value, names):
    if not isinstance(value, dict) or set(value) != set(names.split()):
        raise ValueError("Invalid repository review document fields")


def matches(actual, expected):
    # JSON equality must distinguish booleans from integer sequence numbers.
    def encode(value):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)

    if encode(actual) != encode(expected):
        raise ValueError("Repository review evidence does not match")


def hexadecimal(value, length=64):
    if not isinstance(value, str) or re.fullmatch(rf"[0-9a-f]{{{length}}}", value) is None:
        raise ValueError("Invalid repository review digest")


def capture(bundle):
    descriptor = os.open(bundle, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        return {
            name: read_file(name, maximum, directory=descriptor)
            for name, maximum in {
                "manifest.json": 65536,
                "configuration.json": 65536,
                "commands.json": MAX_ARCHIVE,
                "receipt-binding.json": 1024 * 1024,
                "receipts.ndjson": MAX_RECEIPTS,
                "kernel.pub": 1024,
                "baseline.tar": MAX_ARCHIVE,
                "workspace.tar": MAX_ARCHIVE,
                "changes.patch": 2 * MAX_ARCHIVE,
            }.items()
        }
    finally:
        os.close(descriptor)


def verify_export(bundle, *, binary, repository, revision, key_path, server_id):
    """Check received data without opening private state or launching any tools."""
    if (
        not isinstance(revision, str)
        or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", revision) is None
    ):
        raise ValueError("Review requires an independently selected full source commit")
    if not isinstance(server_id, str) or not server_id or len(server_id.encode()) > 1024:
        raise ValueError("Review requires an expected execution server")
    key = read_file(key_path, 1024)
    data = capture(bundle)
    if key.strip() != data["kernel.pub"].strip():
        raise ValueError("Bundled key differs from the independently trusted kernel key")
    receipts, verification = verified_receipts(binary, data["receipts.ndjson"], key)
    manifest = document(data["manifest.json"])
    config = document(data["configuration.json"])
    proof = document(data["receipt-binding.json"])
    commands = document(data["commands.json"])
    fields(
        config,
        "schema id engine image helper_image source_commit baseline timeout_seconds",
    )
    if (
        config["schema"] not in ("chio.repository.workspace.v1", "chio.repository.workspace.v2")
        or config["source_commit"] != revision
    ):
        raise ValueError("Workspace configuration does not match the selected source commit")
    hexadecimal(config["id"], 32)
    hexadecimal(config["baseline"])
    for name in ("image", "helper_image"):
        if not isinstance(config[name], str) or not config[name].startswith("sha256:"):
            raise ValueError("Invalid repository image identity")
        hexadecimal(config[name][7:])
    if (
        not isinstance(config["engine"], str)
        or not config["engine"]
        or len(config["engine"].encode()) > 1024
        or type(config["timeout_seconds"]) is not int
        or not 1 <= config["timeout_seconds"] <= 300
    ):
        raise ValueError("Invalid repository execution configuration")
    if not isinstance(commands, list) or not 1 <= len(commands) <= MAX_COMMANDS:
        raise ValueError("Review requires a nonempty bounded completed trajectory")
    candidates = [
        receipt
        for receipt in receipts
        if receipt.get("tool_server") == server_id and receipt.get("tool_name") == "execute"
    ]
    if len(candidates) != len(commands) or len({r["id"] for r in candidates}) != len(commands):
        raise ValueError("Receipts do not cover exactly the repository commands")
    transitions, statuses = [], []
    previous = config["baseline"]
    for sequence, row in enumerate(commands, 1):
        fields(row, "sequence command status before_sha256 after_sha256 result")
        if (
            type(row["sequence"]) is not int
            or row["sequence"] != sequence
            or row["status"] != "completed"
            or row["before_sha256"] != previous
            or not isinstance(row["command"], str)
            or not 1 <= len(row["command"].encode()) <= 65536
            or "\0" in row["command"]
        ):
            raise ValueError("Repository commands are incomplete or out of order")
        hexadecimal(row["after_sha256"])
        output = row["result"]
        fields(output, "output returncode exception_info workspace")
        if (
            not isinstance(output["output"], str)
            or type(output["returncode"]) is not int
            or not 0 <= output["returncode"] <= 255
            or output["returncode"] in {124, 137}
            or output["exception_info"] != ""
        ):
            raise ValueError("Invalid repository command output")
        validate_result(output)
        transition = output["workspace"]
        fields(
            transition,
            "id source_commit revision before_sha256 after_sha256 "
            "contents_sha256 configuration_sha256",
        )
        hexadecimal(transition["contents_sha256"])
        matches(
            transition,
            {
                "id": config["id"],
                "source_commit": revision,
                "revision": sequence,
                "before_sha256": previous,
                "after_sha256": row["after_sha256"],
                "contents_sha256": transition["contents_sha256"],
                "configuration_sha256": configuration_digest(config),
            },
        )
        content_hash = output_digest(output)
        matching = [
            receipt
            for receipt in candidates
            if receipt.get("content_hash") == content_hash
            and receipt.get("action", {}).get("parameters", {}).get("command") == row["command"]
            and receipt.get("decision", {}).get("verdict") == "allow"
            and receipt.get("metadata", {}).get("admission_operation", {}).get("projected_state")
            == "completed"
        ]
        if len(matching) != 1:
            raise ValueError("Command or workspace output is not bound to one verified receipt")
        receipt = matching[0]
        candidates.remove(receipt)
        transitions.append(
            {"receipt_id": receipt["id"], "content_hash": content_hash, **transition}
        )
        statuses.append(
            {key: row[key] for key in ("sequence", "status", "before_sha256", "after_sha256")}
        )
        previous = row["after_sha256"]
    # The original archive includes sandbox Git metadata, which exports omit.
    # Authenticate the stripped baseline against the recipient's own Git commit.
    commit, baseline = import_revision(repository, revision)
    matches(commit, revision)
    if data["baseline.tar"] != baseline:
        raise ValueError("Exported baseline differs from the independently selected source")
    workspace = canonical(data["workspace.tar"])
    if workspace != data["workspace.tar"]:
        raise ValueError("Exported workspace archive is not canonical")
    if digest(workspace) != transitions[-1]["contents_sha256"]:
        raise ValueError("Exported workspace differs from the signed final contents")
    if data["changes.patch"] != patch(baseline, workspace):
        raise ValueError("Exported patch differs from the authenticated repository changes")
    matches(
        manifest,
        {
            "schema": "chio.repository.export.v1",
            "id": config["id"],
            "source_commit": revision,
            "revision": len(commands),
            "snapshot": previous,
            "commands": statuses,
            "interrupted": False,
            "baseline": config["baseline"],
            "patch_sha256": digest(data["changes.patch"]),
            "baseline_contents_sha256": digest(baseline),
            "contents_sha256": digest(workspace),
            "image": config["image"],
            "helper_image": config["helper_image"],
        },
    )
    matches(
        proof,
        {
            "schema": "chio.repository.receipt-binding.v1",
            "server_id": server_id,
            "verification": verification,
            "transitions": transitions,
            "receipts_sha256": digest(data["receipts.ndjson"]),
            "kernel_key_sha256": digest(data["kernel.pub"]),
        },
    )
    return {
        "schema": "chio.repository.review.v1",
        "server_id": server_id,
        "source_commit": revision,
        "workspace_id": config["id"],
        "configuration_sha256": configuration_digest(config),
        "patch_sha256": digest(data["changes.patch"]),
        "contents_sha256": digest(workspace),
        "verified_transitions": len(transitions),
        "verification": verification,
    }

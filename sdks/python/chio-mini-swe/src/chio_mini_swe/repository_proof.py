"""Match exported workspace transitions to independently verified Chio receipts."""

import json
import tempfile
from pathlib import Path

from chio_mini_swe.operator import command, protected_executable
from chio_mini_swe.provider_config import reject_constant, unique_object
from chio_mini_swe.repository_archive import contents, digest
from chio_mini_swe.repository_store import atomic_bytes, configuration_digest
from chio_mini_swe.repository_wire import tool_result

# Match the native verifier's aggregate bound. A complete 128-command
# trajectory can contain more than eight MiB of signed command parameters.
MAX_RECEIPTS = 64 * 1024 * 1024


def output_digest(value):
    # Fixed ASCII keys, strings, booleans and bounded integers in this envelope
    # have the same compact UTF-8 representation under RFC 8785. The text
    # member retains the exact JSON string emitted by the MCP service.
    encoded = json.dumps(
        tool_result(value),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
    ).encode()
    return digest(encoded)


def bindings(workspace, receipts, server_id):
    status = workspace.status()
    if status["interrupted"] or not status["commands"]:
        raise ValueError("Receipt binding requires a completed repository trajectory")
    candidates = [
        receipt
        for receipt in receipts
        if receipt.get("tool_server") == server_id and receipt.get("tool_name") == "execute"
    ]
    rows = workspace.db.execute("SELECT * FROM commands ORDER BY sequence").fetchall()
    if len(candidates) != len(rows) or len({r["id"] for r in candidates}) != len(rows):
        raise ValueError("Receipts do not cover exactly the repository commands")
    result, previous = [], workspace.config["baseline"]
    for revision, row in enumerate(rows, 1):
        output = json.loads(row["result"])
        transition = output["workspace"]
        if (
            transition["id"] != workspace.config["id"]
            or transition["configuration_sha256"] != configuration_digest(workspace.config)
            or transition["source_commit"] != workspace.config["source_commit"]
            or transition["revision"] != revision
            or transition["before_sha256"] != row["before_sha256"]
            or row["before_sha256"] != previous
            or transition["after_sha256"] != row["after_sha256"]
            or transition["contents_sha256"]
            != digest(contents(workspace.snapshot(row["after_sha256"])))
        ):
            raise ValueError("Repository snapshot chain does not match the retained results")
        expected = output_digest(output)
        matching = [
            receipt
            for receipt in candidates
            if receipt.get("content_hash") == expected
            and receipt.get("action", {}).get("parameters", {}).get("command") == row["command"]
        ]
        if len(matching) != 1:
            raise ValueError(
                "Receipt output differs from the repository transition; "
                "redacted or changed output cannot prove this binding"
            )
        receipt = matching[0]
        if (
            receipt.get("decision", {}).get("verdict") != "allow"
            or receipt.get("metadata", {}).get("admission_operation", {}).get("projected_state")
            != "completed"
        ):
            raise ValueError("Repository receipt does not attest a completed allowed operation")
        result.append(
            {
                "revision": revision,
                "receipt_id": receipt["id"],
                "content_hash": expected,
                **transition,
            }
        )
        candidates.remove(receipt)
        previous = row["after_sha256"]
    if previous != status["snapshot"] or status["revision"] != len(rows):
        raise ValueError("Repository head differs from the verified trajectory")
    return result


def verified_receipts(binary, data, key):
    """Authenticate captured receipt bytes against an independently supplied key."""
    protected_executable(binary)
    if len(data) > MAX_RECEIPTS:
        raise ValueError("Receipt file exceeds its byte limit")
    receipts = [
        json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant)
        for line in data.splitlines()
        if line.strip()
    ]
    if not receipts or len(receipts) > 1024 or any(not isinstance(r, dict) for r in receipts):
        raise ValueError("Invalid repository receipt count")
    if len(key) > 1024:
        raise ValueError("Trusted kernel public key exceeds its byte limit")
    # Verify the same captured bytes used below, even if the supplied paths
    # are concurrently replaced by the artifact producer.
    with tempfile.TemporaryDirectory(prefix="chio-repository-receipts-") as temporary:
        private = Path(temporary)
        atomic_bytes(private / "receipts.ndjson", data)
        atomic_bytes(private / "kernel.pub", key)
        verification = command(
            binary,
            "--json",
            "receipt",
            "verify",
            "--input",
            private / "receipts.ndjson",
            "--trusted-kernel-pubkey",
            private / "kernel.pub",
        )
    if verification["receipts_verified"] != len(receipts):
        raise ValueError("Not every supplied receipt was verified")
    return receipts, verification


def verify(workspace, *, binary, receipts_path, key_path, server_id):
    with open(receipts_path, "rb") as stream:
        data = stream.read(MAX_RECEIPTS + 1)
    with open(key_path, "rb") as stream:
        key = stream.read(1025)
    receipts, verification = verified_receipts(binary, data, key)
    proof = {
        "schema": "chio.repository.receipt-binding.v1",
        "server_id": server_id,
        "verification": verification,
        "transitions": bindings(workspace, receipts, server_id),
        "receipts_sha256": digest(data),
        "kernel_key_sha256": digest(key),
    }
    return proof, data, key

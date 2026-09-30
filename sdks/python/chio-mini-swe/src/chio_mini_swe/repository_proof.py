"""Match exported workspace transitions to independently verified Chio receipts."""

import json
import tempfile
from pathlib import Path

from chio_process import WorkerError
from chio_process.broker import decode_broker_output

from chio_mini_swe.operator import command, protected_executable
from chio_mini_swe.provider_config import reject_constant, unique_object
from chio_mini_swe.repository_archive import contents, digest
from chio_mini_swe.repository_store import atomic_bytes, configuration_digest

# Match the native verifier's aggregate bound. A complete 128-command
# trajectory can contain more than eight MiB of signed command parameters.
MAX_RECEIPTS = 64 * 1024 * 1024


def canonical_envelope(value, depth=0):
    """RFC 8785 for the closed broker envelope's string and integer vocabulary.

    Reject floats and integers outside the interoperable range rather than
    silently hashing a Python rendering that differs from the Rust signer.
    """

    def ordered(value, depth):
        if depth > 64:
            raise ValueError("Broker envelope nesting exceeds its bound")
        if isinstance(value, dict):
            return {
                key: ordered(value[key], depth + 1)
                for key in sorted(value, key=lambda key: key.encode("utf-16-be"))
            }
        if isinstance(value, list):
            return [ordered(item, depth + 1) for item in value]
        if value is None or isinstance(value, (str, bool)):
            return value
        if type(value) is int and abs(value) < 2**53:
            return value
        raise ValueError("Broker envelope contains an unsupported numeric value")

    return json.dumps(
        ordered(value, depth), ensure_ascii=False, allow_nan=False, separators=(",", ":")
    ).encode()


def output_digest(envelope):
    return digest(canonical_envelope(envelope))


def bound_output(receipt, envelope, output, command, configuration):
    """Join a verified kernel receipt to its original broker request and response."""
    try:
        if receipt.get("content_hash") != output_digest(envelope):
            return False
        value = decode_broker_output(envelope)
        if canonical_envelope(value) != canonical_envelope(output):
            return False
        parameters = receipt["action"]["parameters"]
        if parameters["schema"] != "chio.broker-execute.v1":
            return False
        body = parameters["request"]["body"]
        if (
            not isinstance(body, list)
            or len(body) > 131072
            or any(type(byte) is not int or not 0 <= byte <= 255 for byte in body)
        ):
            return False
        request = json.loads(
            bytes(body), object_pairs_hook=unique_object, parse_constant=reject_constant
        )
        return (
            isinstance(request, dict)
            and {"command", "configuration_sha256"}
            <= set(request)
            <= {"command", "configuration_sha256", "tool_call_id"}
            and request["command"] == command
            and request["configuration_sha256"] == configuration
            and receipt.get("decision", {}).get("verdict") == "allow"
            and receipt.get("metadata", {}).get("admission_operation", {}).get("projected_state")
            == "completed"
        )
    except (KeyError, TypeError, ValueError, UnicodeError, RecursionError, WorkerError):
        return False


def bindings(workspace, receipts, server_id, outputs):
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
    if not isinstance(outputs, dict) or set(outputs) != {receipt["id"] for receipt in candidates}:
        raise ValueError("Original broker outputs must cover exactly the repository receipts")
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
        matching = [
            receipt
            for receipt in candidates
            if bound_output(
                receipt,
                outputs[receipt["id"]],
                output,
                row["command"],
                configuration_digest(workspace.config),
            )
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
                "content_hash": receipt["content_hash"],
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


def verify(workspace, *, binary, receipts_path, key_path, server_id, command_outputs_path):
    with open(receipts_path, "rb") as stream:
        data = stream.read(MAX_RECEIPTS + 1)
    with open(key_path, "rb") as stream:
        key = stream.read(1025)
    with open(command_outputs_path, "rb") as stream:
        captured = stream.read(MAX_RECEIPTS + 1)
    if len(captured) > MAX_RECEIPTS:
        raise ValueError("Broker output evidence exceeds its byte limit")
    outputs = json.loads(captured, object_pairs_hook=unique_object, parse_constant=reject_constant)
    receipts, verification = verified_receipts(binary, data, key)
    proof = {
        "schema": "chio.repository.receipt-binding.v2",
        "server_id": server_id,
        "verification": verification,
        "transitions": bindings(workspace, receipts, server_id, outputs),
        "outputs": outputs,
        "receipts_sha256": digest(data),
        "kernel_key_sha256": digest(key),
    }
    return proof, data, key

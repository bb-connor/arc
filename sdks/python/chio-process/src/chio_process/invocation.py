"""Invoke one scoped tool and retain its request, response and verified receipt.

This command never retries automatically. Keep the operation key, arguments
and recovery policy unchanged when recovering an uncertain invocation.
"""

import argparse
import json
import os
import subprocess
from pathlib import Path

from chio_process import ProcessClient, WorkerError


def _sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write(path, value):
    data = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n"
    _write_text(path, data)


def _write_text(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    _sync_directory(path.parent)


def invoke_recorded(chio, connection, public_key, request, output):
    """Return a receipt-bound result. Transport or verification errors do not retry.

    known_outcome_only defaults to true. It permits first dispatch, then refuses
    redispatch of an unknown outcome. It is not an outcome-query-only operation.
    The connection's capability, not this client, determines permitted tools.
    The host connection supplies the expected runtime, process and capability.
    The separate execution_nonce_json artifact is retained but not verified.
    """
    fields = {
        "operation_key",
        "server_id",
        "tool_name",
        "arguments",
        "known_outcome_only",
    }
    if not isinstance(request, dict) or set(request) - fields:
        raise ValueError("invalid invocation request fields")
    for field in ("operation_key", "server_id", "tool_name"):
        if not isinstance(request.get(field), str) or not request[field]:
            raise ValueError("operation_key, server_id and tool_name are required")
    if not isinstance(request.get("arguments"), dict):
        raise ValueError("invocation arguments must be an object")
    if type(request.get("known_outcome_only", True)) is not bool:
        raise ValueError("known_outcome_only must be a boolean")
    # Normalize the default before recording, so the retained request is explicit.
    request = {**request, "known_outcome_only": request.get("known_outcome_only", True)}
    request = json.loads(json.dumps(request, allow_nan=False))
    context = {}
    for field in ("runtime_id", "process_id", "capability_id"):
        value = connection.get(field)
        if not isinstance(value, str) or not value:
            raise ValueError(f"host connection must supply {field} before dispatch")
        context[field] = value
    chio = Path(chio).resolve(strict=True)
    output = Path(output)
    output.mkdir(mode=0o700)
    _sync_directory(output.parent)
    _write(output / "request.json", request)
    _write(output / "verification-context.json", context)
    _write_text(output / "kernel.pub", public_key)
    client = ProcessClient(connection["socket_path"], connection["credential"])
    try:
        result = client.invoke(
            request["operation_key"],
            request["server_id"],
            request["tool_name"],
            request["arguments"],
            known_outcome_only=request["known_outcome_only"],
        )
    except WorkerError as error:
        _write(
            output / "unresolved.json",
            {
                "error": error.code,
                "completed_response": False,
                "automatic_retry": False,
            },
        )
        raise
    _write(output / "response.json", result)
    # Preserve signed JSON verbatim. A verification failure after invocation
    # does not imply that no resource effect occurred.
    receipt = result.get("receipt_json")
    if not isinstance(receipt, str) or "\n" in receipt:
        raise ValueError("response did not contain one original receipt")
    _write_text(output / "receipts.ndjson", receipt + "\n")
    verified = subprocess.run(
        [
            str(chio),
            "receipt",
            "verify-process-response",
            "--response",
            str(output / "response.json"),
            "--request",
            str(output / "request.json"),
            "--context",
            str(output / "verification-context.json"),
            "--trusted-kernel-pubkey",
            str(output / "kernel.pub"),
        ],
        capture_output=True,
        timeout=90,
    )
    if verified.returncode:
        _write(output / "verification.json", {"receipt_verified": False, "response_bound": False})
        raise RuntimeError("retained response binding did not verify; no automatic retry")
    _write(
        output / "verification.json",
        {
            "receipt_verified": True,
            "response_bound": True,
            "unchecked_fields": ["execution_nonce_json"],
        },
    )
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--connection", type=Path, required=True)
    parser.add_argument("--trusted-kernel-pubkey", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = invoke_recorded(
        args.chio,
        json.loads(args.connection.read_text()),
        args.trusted_kernel_pubkey.read_text(),
        json.loads(args.request.read_text()),
        args.output.resolve(),
    )
    print(
        json.dumps(
            {
                "verdict": result["verdict"],
                "output": result["output"],
                "receipt_verified": True,
                "response_bound": True,
            }
        )
    )


if __name__ == "__main__":
    main()

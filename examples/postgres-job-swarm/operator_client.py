"""Invoke an operator job tool with a stable key and preserve its signed outcome."""

import argparse
import json
import os
from pathlib import Path

import host
from chio_process import ProcessClient, WorkerError


def execute(chio, connection, public_key, request, output):
    """Never retry automatically. Preserve the request before issuing its effect."""
    expected = {"operation_key", "tool_name", "arguments", "known_outcome_only"}
    if not isinstance(request, dict) or set(request) - expected:
        raise ValueError("invalid operator request fields")
    if not isinstance(request.get("operation_key"), str) or not request["operation_key"]:
        raise ValueError("an explicit stable operation_key is required")
    if request.get("tool_name") not in ("assign", "release", "inspect"):
        raise ValueError("unknown operator tool")
    if not isinstance(request.get("arguments"), dict):
        raise ValueError("operator arguments must be an object")
    if type(request.get("known_outcome_only", True)) is not bool:
        raise ValueError("known_outcome_only must be a boolean")
    output.mkdir(mode=0o700)
    host.write(output / "request.json", request)
    (output / "kernel.pub").write_text(public_key)
    client = ProcessClient(connection["socket_path"], connection["credential"])
    try:
        result = client.invoke(
            request["operation_key"],
            "jobs-admin",
            request["tool_name"],
            request["arguments"],
            known_outcome_only=request.get("known_outcome_only", True),
        )
    except WorkerError as error:
        host.write(
            output / "unresolved.json",
            {
                "error": error.code,
                "completed_response": False,
                "automatic_retry": False,
            },
        )
        raise
    host.write(output / "response.json", result)
    # A verification failure after invocation does not imply no resource effect.
    host.verify(chio, output, [result["receipt_json"]])
    return result


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--connection", type=Path, required=True)
    parser.add_argument("--kernel-pubkey", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = execute(
        args.chio.resolve(strict=True),
        json.loads(args.connection.read_text()),
        args.kernel_pubkey.read_text(),
        json.loads(args.request.read_text()),
        args.output.resolve(),
    )
    print(
        json.dumps(
            {"verdict": result["verdict"], "output": result["output"], "receipt_verified": True}
        )
    )


if __name__ == "__main__":
    main()

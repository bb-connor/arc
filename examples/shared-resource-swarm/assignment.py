"""Operator-only assignment through the existing process client and receipt verifier."""

import json

import run
from chio_process.invocation import invoke_recorded


def assign(
    chio,
    directory,
    operation_key,
    document,
    expected_generation,
    owner,
    expected_revision,
    task=None,
):
    request = {
        "operation_key": operation_key,
        "server_id": "board-admin",
        "tool_name": "assign",
        "arguments": {
            "document": document,
            "expected_generation": expected_generation,
            "owner_capability_sha256": owner,
            "expected_revision": expected_revision,
            "task": task,
        },
        "known_outcome_only": True,
    }
    response = invoke_recorded(
        chio,
        json.loads((directory / "root" / "connection.json").read_text()),
        (directory / "kernel.pub").read_text(),
        request,
        directory / ("operator-" + operation_key),
    )
    if response["verdict"] != "allow":
        raise RuntimeError("operator assignment was refused")
    result = response["output"]["value"]
    if result.get("isError") is not False:
        raise RuntimeError("operator assignment was refused")
    value = result["structuredContent"]
    if value.get("status") != "assigned":
        raise RuntimeError("operator assignment conflicts with retained state")
    # These records contain no connection credential and can join public evidence.
    run.write(
        directory / ("operator-" + operation_key + ".json"),
        {
            "request": request,
            "response": response,
            "receipt_verified": True,
        },
    )
    return value


def evidence(directory):
    return [
        json.loads(path.read_text())
        for path in sorted(directory.glob("operator-*.json"))
    ]

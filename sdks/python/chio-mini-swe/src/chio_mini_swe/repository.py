"""Installed repository execution service and review artifact commands."""

import argparse
import json
import os
import signal
import sys

from chio_mini_swe.operator import private_directory, write
from chio_mini_swe.provider_config import reject_constant, unique_object
from chio_mini_swe.repository_archive import contents, digest, patch
from chio_mini_swe.repository_proof import verify
from chio_mini_swe.repository_store import Workspace, atomic_bytes, configuration_digest, initialize
from chio_mini_swe.repository_wire import request_id, response_frame, tool_result


def tool(config):
    config_digest = configuration_digest(config)
    return {
        "name": "execute",
        "description": (
            f"Execute one bash command in repository workspace {config['id']} "
            f"at source commit {config['source_commit']}. Configuration SHA-256: {config_digest}."
        ),
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["command"],
            "properties": {
                "command": {"type": "string", "minLength": 1, "maxLength": 65536},
                "tool_call_id": {"type": "string", "maxLength": 1024},
            },
        },
        "annotations": {
            "readOnlyHint": False,
            "idempotentHint": False,
            "destructiveHint": True,
            "openWorldHint": False,
        },
    }


def serve(workspace, incoming=None, outgoing=None):
    incoming = sys.stdin.buffer if incoming is None else incoming
    outgoing = sys.stdout if outgoing is None else outgoing
    workspace.recover()
    while line := incoming.readline(80 * 1024 + 1):
        if len(line) > 80 * 1024 or not line.endswith(b"\n"):
            raise ValueError("Repository MCP frame exceeds its bound or is incomplete")
        message = json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant)
        if "id" not in message:
            continue
        identifier = request_id(message["id"])
        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "chio-mini-swe-repository", "version": "1"},
            }
        elif method == "tools/list":
            result = {"tools": [tool(workspace.config)]}
        elif method == "tools/call":
            try:
                arguments = message["params"]["arguments"]
                if (
                    message["params"]["name"] != "execute"
                    or not isinstance(arguments, dict)
                    or not {"command"} <= set(arguments) <= {"command", "tool_call_id"}
                ):
                    raise ValueError("Invalid repository tool call")
                if "tool_call_id" in arguments and (
                    not isinstance(arguments["tool_call_id"], str)
                    or len(arguments["tool_call_id"].encode()) > 1024
                ):
                    raise ValueError("Invalid repository tool call ID")
                value = workspace.execute(arguments["command"])
                result = tool_result(value)
            except Exception:
                result = {
                    "isError": True,
                    "content": [
                        {
                            "type": "text",
                            "text": (
                                "Repository execution stopped. "
                                "Inspect the retained operator workspace before continuing."
                            ),
                        }
                    ],
                }
        else:
            raise ValueError("Unsupported repository MCP method")
        print(
            response_frame(identifier, result),
            file=outgoing,
            flush=True,
        )


def export(workspace, output):
    status = workspace.status()
    if any(row["status"] == "pending" for row in status["commands"]):
        raise ValueError("Recover pending repository containers before exporting retained state")
    before = contents(workspace.snapshot(workspace.config["baseline"]))
    after = contents(workspace.snapshot(status["snapshot"]))
    difference = patch(before, after)
    output = private_directory(output, create=True)
    for name, data in [
        ("baseline.tar", before),
        ("workspace.tar", after),
        ("changes.patch", difference),
    ]:
        atomic_bytes(output / name, data)
    commands = [
        dict(row)
        for row in workspace.db.execute(
            "SELECT sequence,command,status,before_sha256,after_sha256,result "
            "FROM commands ORDER BY sequence"
        )
    ]
    for row in commands:
        if row["result"] is not None:
            row["result"] = json.loads(row["result"])
    write(output / "commands.json", commands)
    manifest = {
        "schema": "chio.repository.export.v1",
        **status,
        "baseline": workspace.config["baseline"],
        "patch_sha256": digest(difference),
        "baseline_contents_sha256": digest(before),
        "contents_sha256": digest(after),
        "image": workspace.config["image"],
        "helper_image": workspace.config["helper_image"],
    }
    manifest["schema"] = "chio.repository.export.v1"
    write(output / "manifest.json", manifest)
    return {
        "output": str(output),
        "revision": status["revision"],
        "interrupted": status["interrupted"],
        "patch_sha256": digest(difference),
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run repository commands through a private Chio execution service"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("init")
    setup.add_argument("--repository", required=True)
    setup.add_argument("--revision", default="HEAD")
    setup.add_argument("--image", required=True)
    setup.add_argument("--helper-image", required=True)
    setup.add_argument("--timeout-seconds", type=int, default=60)
    for command in [
        setup,
        *(commands.add_parser(name) for name in ("serve", "status", "recover", "export", "verify")),
    ]:
        command.add_argument("--state", required=True)
        if command.prog.endswith((" export", " verify")):
            command.add_argument("--out", required=True)
        if command.prog.endswith(" verify"):
            command.add_argument("--chio", required=True)
            command.add_argument("--receipts", required=True)
            command.add_argument("--kernel-key", required=True)
            command.add_argument("--server-id", required=True)
    args = parser.parse_args()
    os.umask(0o077)

    def stop(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, stop)
    if args.command == "init":
        value = initialize(
            args.repository,
            args.revision,
            args.image,
            args.helper_image,
            args.state,
            args.timeout_seconds,
        )
    else:
        with Workspace(args.state) as workspace:
            if args.command == "serve":
                serve(workspace)
                return 0
            if args.command == "recover":
                workspace.recover()
            if args.command == "verify":
                proof, receipts, key = verify(
                    workspace,
                    binary=args.chio,
                    receipts_path=args.receipts,
                    key_path=args.kernel_key,
                    server_id=args.server_id,
                )
                value = export(workspace, args.out)
                atomic_bytes(private_directory(args.out) / "receipts.ndjson", receipts)
                atomic_bytes(private_directory(args.out) / "kernel.pub", key)
                write(private_directory(args.out) / "receipt-binding.json", proof)
                value["verified_transitions"] = len(proof["transitions"])
            else:
                value = (
                    export(workspace, args.out) if args.command == "export" else workspace.status()
                )
    print(json.dumps(value, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

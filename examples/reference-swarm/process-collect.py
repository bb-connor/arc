"""Verify reader responses against operator-pinned identity and input hashes.

This checks a useful result. Complete M5 accounting, terminal authority and
confinement-chain verification remain separate acceptance requirements.
"""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["chio", "evidence", "inputs", "trusted-kernel-pubkey", "output"]:
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    expected = json.loads(args.inputs.read_text())
    if expected["schema"] != "chio.reference-swarm.inputs.v1":
        raise ValueError("unsupported input manifest")
    inputs = expected["files"]
    if not 2 <= len(inputs) <= 32 or len({item["process"] for item in inputs}) != len(
        inputs
    ):
        raise ValueError("invalid reader inventory")
    results = []
    for item in inputs:
        process = item["process"]
        if not process.startswith("reader-") or not process[7:].isdigit():
            raise ValueError("invalid reader identity")
        directory = args.evidence / process
        request = json.loads((directory / "request.json").read_text())
        context = json.loads((directory / "context.json").read_text())
        if (
            context
            != {
                "runtime_id": expected["runtime_id"],
                "process_id": process,
                "capability_id": item["capability_id"],
            }
            or request["operation_key"] != "read-source"
        ):
            raise ValueError(
                f"{process}: worker identity differs from the operator's plan"
            )
        if (
            request["server_id"],
            request["tool_name"],
            request["arguments"],
            context["process_id"],
        ) != ("reference-reader", "read_file", {"path": item["path"]}, process):
            raise ValueError(f"{process}: response does not describe the planned input")
        subprocess.run(
            [
                str(args.chio.resolve(strict=True)),
                "--json",
                "receipt",
                "verify-process-response",
                "--request",
                str(directory / "request.json"),
                "--context",
                str(directory / "context.json"),
                "--response",
                str(directory / "response.json"),
                "--trusted-kernel-pubkey",
                str(args.trusted_kernel_pubkey),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        response = json.loads((directory / "response.json").read_text())
        if (
            response["verdict"] != "allow"
            or response["request_id"] != item["request_id"]
        ):
            raise ValueError(f"{process}: planned read was not allowed")
        result = response["output"]["structuredContent"]
        content = result["content"].encode("utf-8")
        digest = hashlib.sha256(content).hexdigest()
        if (result["path"], result["truncated"], len(content), digest) != (
            item["path"],
            False,
            item["bytes"],
            item["sha256"],
        ):
            raise ValueError(
                f"{process}: returned content differs from the operator's input snapshot"
            )
        results.append(
            {
                **item,
                "lines": len(result["content"].splitlines()),
                "request_id": response["request_id"],
            }
        )
    report = {
        "schema": "chio.reference-swarm.repository-report.v1",
        "files": results,
        "total_bytes": sum(item["bytes"] for item in results),
        "m5_acceptance_complete": False,
    }
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2)
        stream.write("\n")
    print(json.dumps(report))


if __name__ == "__main__":
    main()

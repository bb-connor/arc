"""Measure fresh dispatch, retained replay and receipt verification separately.

The direct MCP baseline uses the same persistent resource operation journal.
Both routes must return the same document. Kernel receipts and the actual
resource delivery counters are checked before a latency report is accepted.
This serial local diagnostic does not measure model performance or adoption.
"""

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import time
from pathlib import Path

import run
import store
from chio_process import ProcessClient
from chio_process.invocation import invoke_recorded
from chio_process.launch import demo_python
from mcp_client import McpClient


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--build-profile", choices=("dev", "docker-release", "release"), required=True
    )
    parser.add_argument("--binary-source-commit", required=True)
    parser.add_argument("--rounds", type=int, default=20)
    args = parser.parse_args()
    if not 5 <= args.rounds <= 32:
        parser.error("rounds must be between 5 and 32")
    if len(args.binary_source_commit) != 40 or any(
        c not in "0123456789abcdef" for c in args.binary_source_commit
    ):
        parser.error("binary source commit must be a full lowercase Git SHA")
    directory = args.output.resolve()
    directory.mkdir(mode=0o700)
    (directory / "benchmark").mkdir(mode=0o700)
    seed = json.loads((run.HERE / "seed.json").read_text())
    store.initialize(directory / "resource.db", seed)
    store.initialize(directory / "baseline.db", seed)
    started = time.perf_counter()
    binary, key = run.prepare_host(args, directory, roles=("benchmark",))
    setup_seconds = time.perf_counter() - started
    connection = json.loads((directory / "benchmark/connection.json").read_text())
    client = ProcessClient(connection["socket_path"], connection["credential"])
    samples, receipts, originals = [], [], {}
    arguments = {"document": "release-board"}

    def native(operation):
        response = client.invoke(
            operation, "board", "snapshot", arguments, known_outcome_only=True
        )
        assert response["verdict"] == "allow"
        assert response["output"]["value"]["isError"] is False
        receipts.append(response["receipt_json"])
        if operation in originals:
            assert originals[operation] == response["receipt_json"]
        else:
            originals[operation] = response["receipt_json"]
        return response["output"]["value"]

    command = [
        demo_python(),
        str(run.HERE / "server.py"),
        "--database",
        str(directory / "baseline.db"),
        "--connection-caller",
        connection["caller_capability_sha256"],
    ]
    started = time.perf_counter()
    baseline = McpClient(command)
    baseline_start_seconds = time.perf_counter() - started
    started = time.perf_counter()
    try:
        with run.host(binary, key, directory):
            host_start_seconds = time.perf_counter() - started
            assert native("warmup") == baseline.invoke("warmup", "snapshot", arguments)
            for phase in ("fresh", "replay"):
                for index in range(args.rounds):
                    returned = []
                    for backend in (
                        ("baseline", "chio") if index % 2 == 0 else ("chio", "baseline")
                    ):
                        before = time.perf_counter_ns()
                        operation = f"probe-{index}"
                        response = (
                            native(operation)
                            if backend == "chio"
                            else baseline.invoke(operation, "snapshot", arguments)
                        )
                        elapsed_ns = time.perf_counter_ns() - before
                        returned.append(response)
                        samples.append(
                            {
                                "phase": phase,
                                "backend": backend,
                                "round": index,
                                "elapsed_ns": elapsed_ns,
                            }
                        )
                    assert returned[0] == returned[1]
            for phase in ("fresh", "replay"):
                for index in range(5):
                    operation = f"recorded-{index}"
                    before = time.perf_counter_ns()
                    response = invoke_recorded(
                        binary,
                        connection,
                        key + "\n",
                        {
                            "operation_key": operation,
                            "server_id": "board",
                            "tool_name": "snapshot",
                            "arguments": arguments,
                        },
                        directory / f"{phase}-{index}",
                    )
                    elapsed_ns = time.perf_counter_ns() - before
                    assert response["verdict"] == "allow"
                    assert response["output"]["value"]["isError"] is False
                    receipts.append(response["receipt_json"])
                    if operation in originals:
                        assert originals[operation] == response["receipt_json"]
                    else:
                        originals[operation] = response["receipt_json"]
                    samples.append(
                        {
                            "phase": phase,
                            "backend": "chio_recorded_verified",
                            "round": index,
                            "elapsed_ns": elapsed_ns,
                        }
                    )
    finally:
        baseline.close()
    resources = {
        name: store.inspect(directory / file)
        for name, file in [("baseline", "baseline.db"), ("chio", "resource.db")]
    }
    assert all(len(r["mutations"]) == 0 for r in resources.values())
    for backend, resource in resources.items():
        deliveries = [o["deliveries"] for o in resource["operations"]]
        assert len(deliveries) == (
            args.rounds + 1 if backend == "baseline" else args.rounds + 6
        )
        assert sorted(deliveries) == (
            [1] + [2] * args.rounds
            if backend == "baseline"
            else [1] * (args.rounds + 6)
        )
    (directory / "receipts.ndjson").write_text(
        "\n".join(dict.fromkeys(receipts)) + "\n"
    )
    started = time.perf_counter()
    subprocess.run(
        [
            str(binary),
            "receipt",
            "verify",
            "--input",
            str(directory / "receipts.ndjson"),
            "--trusted-kernel-pubkey",
            str(directory / "kernel.pub"),
        ],
        check=True,
    )
    verification_seconds = time.perf_counter() - started
    groups = []
    for backend in ["baseline", "chio", "chio_recorded_verified"]:
        for phase in ["fresh", "replay"]:
            values = [
                s["elapsed_ns"] / 1e6
                for s in samples
                if s["backend"] == backend and s["phase"] == phase
            ]
            groups.append(
                {
                    "backend": backend,
                    "phase": phase,
                    "count": len(values),
                    "median_ms": statistics.median(values),
                    "minimum_ms": min(values),
                    "maximum_ms": max(values),
                }
            )
    report = {
        "schema": "chio.shared-resource.dispatch-probe.v1",
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=run.HERE.parent.parent, text=True
        ).strip(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "build_profile": args.build_profile,
        "binary_source_commit": args.binary_source_commit,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "task": "unchanged document snapshot with durable resource operation retention",
        "live_model": False,
        "chio_operator_provisioning_seconds": setup_seconds,
        "chio_host_start_seconds": host_start_seconds,
        "baseline_server_start_seconds": baseline_start_seconds,
        "batch_verification_seconds": verification_seconds,
        "verified_unique_receipts": len(set(receipts)),
        "samples": samples,
        "groups": groups,
        "resource_operation_counts": {
            k: len(v["operations"]) for k, v in resources.items()
        },
        "resource_deliveries": {
            backend: {
                operation["id"]: operation["deliveries"]
                for operation in resource["operations"]
            }
            for backend, resource in resources.items()
        },
        "limits": [
            "Single-host serial diagnostic, not concurrent throughput or end-to-end agent performance. Build-profile labels require matching build provenance.",
            "Baseline has persistent resource request identity and deduplication but no Chio authority mediation or signed kernel receipts.",
            "Known completed replay measured, not uncertain redispatch.",
            "No installation time, model latency or human setup effort is included.",
        ],
    }
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        json.dumps(
            {
                k: report[k]
                for k in [
                    "chio_operator_provisioning_seconds",
                    "chio_host_start_seconds",
                    "baseline_server_start_seconds",
                    "batch_verification_seconds",
                    "groups",
                ]
            }
        )
    )


if __name__ == "__main__":
    main()

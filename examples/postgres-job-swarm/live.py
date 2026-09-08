"""Run a live handoff between Python and JavaScript workers on PostgreSQL jobs."""

import argparse
import contextlib
import hashlib
import json
import os
import secrets
import shutil
import subprocess
import sys
import time
from pathlib import Path

import host
import operator_client
import postgres
from chio_process import ProcessClient

SHARED = Path(__file__).resolve().parent.parent / "shared-resource-swarm"
INSTRUCTION = (
    "The assignment list contains your job ID. Read its task evidence with jobs__task. "
    "Assess the release from p95_ms and maximum_p95_ms: blocked if p95 exceeds the maximum, "
    "otherwise ready. Refresh jobs__task immediately before completing so you use its "
    "current lease_fence as expected_fence. Use jobs__complete with result exactly "
    "{release: the task release, status: ready or blocked, p95_ms: the task measurement, "
    "maximum_p95_ms: the task maximum}. Do not claim completion before status completed. "
    "If the tool returns superseded, stop and report that your assignment moved. "
    "Do not retry a superseded completion. already_completed reports an existing resource "
    "result and does not mean you committed a new result."
)


def structured(response):
    if response["verdict"] != "allow" or response["output"]["value"].get("isError") is not False:
        raise AssertionError("resource call was not allowed")
    return response["output"]["value"]["structuredContent"]


def worker_environment(provider):
    names = ("PATH", "HOME", "TMPDIR", "SYSTEMROOT", "SSL_CERT_FILE", "SSL_CERT_DIR")
    return {
        **{name: os.environ[name] for name in names if name in os.environ},
        provider.upper() + "_API_KEY": os.environ[provider.upper() + "_API_KEY"],
    }


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--gateway", type=Path, required=True)
    parser.add_argument("--database-state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--consumer", type=Path, required=True)
    parser.add_argument("--old-framework", choices=("langgraph", "ai-sdk"), default="langgraph")
    parser.add_argument("--provider", choices=("openai", "openrouter"), default="openrouter")
    parser.add_argument("--model", required=True)
    parser.add_argument("--node", default=shutil.which("node") or "node")
    args = parser.parse_args()
    environment = worker_environment(args.provider)
    directory = args.output.resolve()
    directory.mkdir(mode=0o700)
    chio, gateway = args.chio.resolve(strict=True), args.gateway.resolve(strict=True)
    state = json.loads(args.database_state.read_text())
    tenant, job_id = "live-agent-jobs-" + secrets.token_hex(6), "assessment"
    payload = {
        "job_id": job_id,
        "task": {"release": "search-3", "p95_ms": 160, "maximum_p95_ms": 120},
    }
    host.write(directory / "input.json", payload)
    created = json.loads(
        host.command(
            [gateway, "seed", tenant],
            directory,
            env=postgres.database_env(state, "runtime"),
            input=(json.dumps(payload) + "\n").encode(),
        )
    )
    assert created["created"]
    database_environment = postgres.database_env(state, "worker")
    key, connections = host.prepare(chio, gateway, tenant, directory, database_environment)
    callers = {name: c["caller_capability_sha256"] for name, c in connections.items()}
    consumer = args.consumer.resolve(strict=True)
    source = SHARED / "ai_sdk_worker.mjs"
    staged = consumer / "shared-resource-worker.mjs"
    shutil.copyfile(source, staged)
    subprocess.run(
        [args.node, str(staged), "--preflight", str(consumer)],
        check=True,
        timeout=30,
        capture_output=True,
        env=environment,
    )
    frameworks = {
        "superseded": args.old_framework,
        "replacement": "ai-sdk" if args.old_framework == "langgraph" else "langgraph",
    }
    observations, receipts, phases = [], [], []
    operator_count = 0

    def operate(operation, tool, arguments):
        nonlocal operator_count
        operator_count += 1
        response = operator_client.execute(
            chio,
            connections["root"],
            key + "\n",
            {
                "operation_key": operation,
                "tool_name": tool,
                "arguments": arguments,
                "known_outcome_only": True,
            },
            directory / f"operator-{operator_count}",
        )
        observations.append(
            {"operation": operation, "tool": tool, "arguments": arguments, "response": response}
        )
        receipts.append(response["receipt_json"])
        return structured(response)

    def launch(stack, name):
        settings = {
            "backend": "chio",
            "directory": str(directory / name),
            "services": [job_id],
            "model": args.model,
            "provider": args.provider,
            "thread_id": name,
            "max_rounds": 8,
            "instruction": INSTRUCTION,
            "tools": connections[name]["tools"],
            "namespace": "postgres-job-v1",
            "task_tool_name": "jobs__task",
            "pause_after_task": name == "superseded",
        }
        command = [sys.executable, str(SHARED / "langgraph_worker.py")]
        if frameworks[name] == "ai-sdk":
            settings.update(
                consumer=str(consumer),
                worker_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            )
            command = [args.node, str(staged)]
        log = stack.enter_context((directory / name / "stderr.log").open("ab"))
        process = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, env=environment
        )
        stack.callback(host.stop, process)
        stack.callback(process.stdout.close)
        process.stdin.write(
            json.dumps({"input": settings, "connection": connections[name]}).encode()
        )
        process.stdin.close()
        process.stdin = None
        return process

    def finish(process, name):
        stdout, _ = process.communicate(timeout=300)
        (directory / name / "stdout.log").write_bytes(stdout)
        if process.returncode:
            raise RuntimeError("worker did not finish; inspect private worker logs")
        result = json.loads((directory / name / "result.json").read_text())
        assert result["graph_finished"]
        assert result["model_calls"] and all(
            c["kind"] == "live_" + args.provider and c["complete"] for c in result["model_calls"]
        )
        worker_receipts = [tool["artifact"]["chio"]["receipt_json"] for tool in result["tools"]]
        receipts.extend(worker_receipts)
        return {
            field: result[field] for field in ("graph_finished", "model_calls", "versions", "text")
        } | {
            "framework": frameworks[name],
            "receipts": worker_receipts,
        }

    with contextlib.ExitStack() as stack:
        stack.enter_context(host.serve(chio, directory, key, database_environment))
        assignment = {
            "owner_capability_sha256": callers["superseded"],
            "lease_seconds": 600,
            "limit": 1,
        }
        assigned = operate("initial-assignment", "assign", assignment)["jobs"]
        assert len(assigned) == 1 and assigned[0]["job_id"] == job_id
        original_fence = assigned[0]["lease_fence"]
        old = launch(stack, "superseded")
        marker = directory / "superseded" / "paused.json"
        deadline = time.monotonic() + 180
        while not marker.exists():
            if old.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("old worker did not reach its first task barrier")
            time.sleep(0.05)
        phases.append(
            {
                "phase": "old_paused",
                "job": operate("paused-snapshot", "inspect", {"job_id": job_id}),
            }
        )
        assert phases[-1]["job"]["result"] is None
        assert (
            operate(
                "release-original",
                "release",
                {
                    "job_id": job_id,
                    "owner_capability_sha256": callers["superseded"],
                    "expected_fence": original_fence,
                },
            )["status"]
            == "released"
        )
        replacement = operate(
            "replacement-assignment",
            "assign",
            {
                **assignment,
                "owner_capability_sha256": callers["replacement"],
            },
        )["jobs"]
        assert len(replacement) == 1 and replacement[0]["lease_fence"] > original_fence
        current_fence = replacement[0]["lease_fence"]
        # The old live worker resumes before the replacement starts. Terminal
        # result immutability cannot be responsible for rejecting its write.
        host.write(directory / "superseded" / "release.json", {"released": True})
        old_result = finish(old, "superseded")
        before = operate("old-finished-snapshot", "inspect", {"job_id": job_id})
        phases.append({"phase": "old_finished_before_replacement", "job": before})
        assert (
            before["result"] is None and before["owner_capability_sha256"] == callers["replacement"]
        )
        current = launch(stack, "replacement")
        new_result = finish(current, "replacement")
        final = operate("final-snapshot", "inspect", {"job_id": job_id})
        phases.append({"phase": "replacement_finished", "job": final})
        # Read retained process outcomes for the exact calls selected by the models.
        attempted = []
        for name, result in (("superseded", old_result), ("replacement", new_result)):
            for raw in result["receipts"]:
                receipt = json.loads(raw)
                attribution = receipt.get("metadata", {}).get("chio_process", {})
                connection = connections[name]
                recovered = ProcessClient(
                    connection["socket_path"], connection["credential"]
                ).invoke(
                    attribution["operation_key"],
                    receipt["tool_server"],
                    receipt["tool_name"],
                    receipt["action"]["parameters"],
                    known_outcome_only=attribution.get("recovery_policy") == "known_outcome_only",
                )
                assert recovered["receipt_json"] == raw
                if receipt["tool_name"] == "complete":
                    attempted.append(
                        {
                            "worker": name,
                            "arguments": receipt["action"]["parameters"],
                            "result": structured(recovered),
                            "receipt_json": raw,
                        }
                    )

    host.verify(chio, directory, receipts)
    accepted = final["state"] == "completed" and final["result"] == {
        "release": "search-3",
        "status": "blocked",
        "p95_ms": 160,
        "maximum_p95_ms": 120,
    }
    old_attempts = [a for a in attempted if a["worker"] == "superseded"]
    refused_current = any(
        a["arguments"]["expected_fence"] == current_fence
        and a["result"] == {"status": "superseded"}
        for a in old_attempts
    )
    accepted = (
        accepted
        and refused_current
        and all(a["result"] == {"status": "superseded"} for a in old_attempts)
    )
    report = {
        "schema": "chio.postgres-job.live-handoff.v1",
        "live_model": True,
        "model": args.model,
        "provider": args.provider,
        "tenant": tenant,
        "input": payload,
        "workers": {"superseded": old_result, "replacement": new_result},
        "phases": phases,
        "operator_calls": observations,
        "completion_attempts": attempted,
        "old_caller_with_current_fence_refused": refused_current,
        "callers": callers,
        "original_fence": original_fence,
        "current_fence": current_fence,
        "old_finished_before_replacement": True,
        "receipts_verified": True,
        "accepted": accepted,
        "gateway_sha256": hashlib.sha256(gateway.read_bytes()).hexdigest(),
        "chio_sha256": hashlib.sha256(chio.read_bytes()).hexdigest(),
        "postgres": state["postgres_version"],
        "image_id": state["image_id"],
    }
    host.write(directory / "report.json", report)
    print(
        json.dumps(
            {
                "accepted": accepted,
                "frameworks": frameworks,
                "model_responses": sum(len(r["model_calls"]) for r in (old_result, new_result)),
            }
        )
    )


if __name__ == "__main__":
    main()

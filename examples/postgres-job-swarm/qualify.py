"""Qualify the PostgreSQL lease adapter through the real native Chio host."""

import argparse
import hashlib
import json
import os
import secrets
import subprocess
from pathlib import Path

import host
import postgres
from chio_process import ProcessClient
from chio_process.invocation import invoke_recorded


def value(response):
    if response["verdict"] != "allow":
        raise AssertionError("unexpected kernel denial")
    output = response["output"]["value"]
    if output.get("isError") is not False:
        raise AssertionError("unexpected resource error")
    return output["structuredContent"]


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--database-state", type=Path, required=True)
    parser.add_argument("--gateway", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    chio = args.chio.resolve(strict=True)
    state = json.loads(args.database_state.read_text())
    gateway = (args.gateway or Path(state["binary"])).resolve(strict=True)
    gateway_sha256 = hashlib.sha256(gateway.read_bytes()).hexdigest()
    if args.gateway is None and gateway_sha256 != state["binary_sha256"]:
        raise ValueError("gateway changed since database setup")
    directory = args.output.resolve()
    directory.mkdir(mode=0o700)
    tenant = "agent-jobs-" + secrets.token_hex(6)
    job_id = "assessment"
    payload = {
        "job_id": job_id,
        "task": {
            "instruction": "Assess search-3 release readiness from p95 latency.",
            "p95_ms": 160,
            "maximum_p95_ms": 120,
            "release": "search-3",
        },
    }
    host.write(directory / "input.json", payload)
    seed = json.loads(
        host.command(
            [gateway, "seed", tenant],
            directory,
            env=postgres.database_env(state, "runtime"),
            input=(json.dumps(payload) + "\n").encode(),
        )
    )
    assert seed["created"]
    environment = postgres.database_env(state, "worker")
    # The database role is supplied only to the native host and its tool servers.
    # No model process or connection descriptor receives a database credential.
    key, connections = host.prepare(chio, gateway, tenant, directory, environment)
    callers = {name: c["caller_capability_sha256"] for name, c in connections.items()}
    assert len(set(callers.values())) == 3
    clients = {
        name: ProcessClient(c["socket_path"], c["credential"])
        for name, c in connections.items()
    }
    receipts, observations = [], []
    operator_count = 0

    def invoke(who, operation, tool, arguments, **extra):
        extra.setdefault("known_outcome_only", True)
        result = clients[who].invoke(operation, "jobs", tool, arguments, **extra)
        receipts.append(result["receipt_json"])
        observations.append(
            {
                "who": who,
                "key": operation,
                "tool": tool,
                "arguments": arguments,
                "response": result,
            }
        )
        return result

    def operate(operation, tool, arguments, *, known=True):
        nonlocal operator_count
        operator_count += 1
        result = invoke_recorded(
            chio,
            connections["root"],
            key + "\n",
            {
                "operation_key": operation,
                "server_id": "jobs-admin",
                "tool_name": tool,
                "arguments": arguments,
                "known_outcome_only": known,
            },
            directory / f"operator-{operator_count}",
        )
        receipts.append(result["receipt_json"])
        observations.append(
            {
                "who": "root",
                "key": operation,
                "tool": tool,
                "arguments": arguments,
                "response": result,
            }
        )
        return result

    with host.serve(chio, directory, key, environment):
        assignment = {
            "owner_capability_sha256": callers["superseded"],
            "lease_seconds": 600,
            "limit": 1,
        }
        first = operate("assign-original", "assign", assignment)
        first_job = value(first)["jobs"][0]
        first_fence = first_job["lease_fence"]
        assert first_job["owner_capability_sha256"] == callers["superseded"]
        # Keep the original recovery policy as well as its key and arguments.
        # This policy dispatches new calls but never redispatches unknown outcomes.
        recovered = operate("assign-original", "assign", assignment, known=True)
        assert recovered["receipt_json"] == first["receipt_json"]

        released = operate(
            "release-original",
            "release",
            {
                "job_id": job_id,
                "owner_capability_sha256": callers["superseded"],
                "expected_fence": first_fence,
            },
        )
        assert value(released)["status"] == "released"
        pending = value(operate("inspect-pending", "inspect", {"job_id": job_id}))
        assert pending["state"] == "pending"
        second = operate(
            "assign-replacement",
            "assign",
            {
                **assignment,
                "owner_capability_sha256": callers["replacement"],
            },
        )
        second_job = value(second)["jobs"][0]
        fence = second_job["lease_fence"]
        assert fence > first_fence
        assert second_job["owner_capability_sha256"] == callers["replacement"]

        current = value(
            invoke("superseded", "read-current-fence", "task", {"job_id": job_id})
        )
        assert current["lease_fence"] == fence
        incorrect = {
            "job_id": job_id,
            "expected_fence": fence,
            "result": {"release": "search-3", "status": "ready"},
        }
        refused = value(
            invoke("superseded", "old-current-fence-write", "complete", incorrect)
        )
        assert refused == {"status": "superseded"}
        renewal = value(
            invoke(
                "superseded",
                "old-current-fence-renew",
                "renew",
                {
                    "job_id": job_id,
                    "expected_fence": fence,
                    "lease_seconds": 600,
                },
            )
        )
        assert renewal == {"status": "superseded"}
        spoofed = invoke(
            "superseded",
            "spoof-owner",
            "complete",
            {
                **incorrect,
                "_meta": {"chioCallerCapabilitySha256": callers["replacement"]},
            },
        )
        assert (
            spoofed["verdict"] != "allow"
            or spoofed["output"]["value"].get("isError") is True
        )
        escalation = clients["superseded"].invoke(
            "worker-cannot-assign",
            "jobs-admin",
            "assign",
            assignment,
        )
        receipts.append(escalation["receipt_json"])
        assert escalation["verdict"] == "deny"
        observations.append({"who": "superseded", "operator_route": escalation})

        before = value(
            operate("inspect-before-completion", "inspect", {"job_id": job_id})
        )
        assert before["result"] is None
        assert before["owner_capability_sha256"] == callers["replacement"]
        assert before["lease_fence"] == fence
        correct = {
            "job_id": job_id,
            "expected_fence": fence,
            "result": {
                "release": "search-3",
                "status": "blocked",
                "p95_ms": 160,
                "maximum_p95_ms": 120,
            },
        }
        completed = invoke("replacement", "complete-replacement", "complete", correct)
        assert value(completed) == {"status": "completed"}

    # A real host restart, using retained process state and the same logical keys.
    with host.serve(chio, directory, key, environment):
        replay = invoke(
            "replacement",
            "complete-replacement",
            "complete",
            correct,
            known_outcome_only=True,
        )
        assert replay["receipt_json"] == completed["receipt_json"]
        # Resource deduplication is distinguished from the original kernel outcome.
        duplicate = value(
            invoke("replacement", "same-result-new-logical-call", "complete", correct)
        )
        assert duplicate == {"status": "already_completed"}
        conflicting = value(
            invoke("superseded", "different-terminal-result", "complete", incorrect)
        )
        assert conflicting == {"status": "result_conflict"}
        final = value(operate("inspect-final", "inspect", {"job_id": job_id}))
        assert final["state"] == "completed" and final["result"] == correct["result"]

    # A direct pipe without kernel metadata must not become an implicit caller.
    frames = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "complete", "arguments": correct},
        },
    ]
    raw = subprocess.run(
        [str(gateway), "worker", tenant],
        input=("\n".join(json.dumps(f) for f in frames) + "\n").encode(),
        capture_output=True,
        env=environment,
        timeout=30,
        check=True,
    )
    assert json.loads(raw.stdout)["result"]["isError"] is True
    host.verify(chio, directory, receipts)
    host.write(
        directory / "qualification.json",
        {
            "schema": "chio.postgres-job.native-qualification.v1",
            "evidence_kind": "scripted_native_postgres_job_ownership",
            "live_model": False,
            "tenant": tenant,
            "input": payload,
            "callers": callers,
            "observations": observations,
            "pending_between_release_and_claim": pending,
            "before_completion": before,
            "final": final,
            "original_assignment_receipt_recovered": True,
            "original_completion_receipt_recovered_after_host_restart": True,
            "old_caller_with_current_fence_refused": True,
            "missing_caller_refused": True,
            "worker_operator_route_refused": True,
            "model_owner_spoof_refused": True,
            "receipts_verified": True,
            "resource_deduplication_distinguished": True,
            "postgres": state["postgres_version"],
            "image_id": state["image_id"],
            "repo_digests": state["repo_digests"],
            "gateway_sha256": gateway_sha256,
            "chio_sha256": hashlib.sha256(chio.read_bytes()).hexdigest(),
            "qualified": True,
        },
    )
    print(
        json.dumps(
            {
                "qualified": True,
                "current_fence": fence,
                "old_caller_refused": True,
                "receipts_verified": True,
            }
        )
    )


if __name__ == "__main__":
    main()

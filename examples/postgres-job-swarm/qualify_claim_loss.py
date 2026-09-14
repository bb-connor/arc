"""Kill the native host after PostgreSQL claims a job but before its response.

Recovery must retain uncertainty and must not consume the second queued job.
A separate new-intent control then proves that the second job was claimable.
No model or mocked resource participates in this qualification.
"""

import argparse
import hashlib
import json
import os
import secrets
import signal
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import host
import postgres
from chio_process import WorkerError
from chio_process.invocation import invoke_recorded
from qualify import value

HERE = Path(__file__).resolve().parent


def wait_for(path, *, invocation=None):
    deadline = time.monotonic() + 30
    while not path.exists():
        if invocation is not None and invocation.done():
            invocation.result()
            raise AssertionError("invocation completed without the claim fault")
        if time.monotonic() >= deadline:
            raise TimeoutError("claim fault marker was not reached")
        time.sleep(0.05)
    # The writer creates the file before finishing its bytes. Wait for a full
    # JSON frame instead of treating an empty/partial marker as the cut point.
    while time.monotonic() < deadline:
        try:
            return json.loads(path.read_text())
        except json.JSONDecodeError:
            time.sleep(0.01)
    raise TimeoutError("claim fault marker was incomplete")


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
    gateway_hash = hashlib.sha256(gateway.read_bytes()).hexdigest()
    if args.gateway is None and gateway_hash != state["binary_sha256"]:
        raise ValueError("gateway changed since database setup")
    directory = args.output.resolve()
    directory.mkdir(mode=0o700)
    fault = directory / "fault"
    fault.mkdir(mode=0o700)
    tenant = "claim-loss-" + secrets.token_hex(6)
    jobs = ("assessment-a", "assessment-b")
    for job in jobs:
        seed = json.loads(
            host.command(
                [gateway, "seed", tenant],
                directory,
                env=postgres.database_env(state, "runtime"),
                input=(
                    json.dumps({"job_id": job, "task": {"check": job}}) + "\n"
                ).encode(),
            )
        )
        assert seed["created"]
    environment = postgres.database_env(state, "worker")
    key, connections = host.prepare(
        chio,
        gateway,
        tenant,
        directory,
        environment,
        operator_command=[
            sys.executable,
            str(HERE / "claim_proxy.py"),
            "--evidence",
            str(fault),
            str(gateway),
            tenant,
        ],
    )
    original_connection = connections["root"]
    connection = original_connection
    request = {
        "operation_key": "claim-original",
        "server_id": "jobs-admin",
        "tool_name": "assign",
        "arguments": {
            "owner_capability_sha256": connections["superseded"][
                "caller_capability_sha256"
            ],
            "lease_seconds": 600,
            "limit": 1,
        },
        "known_outcome_only": True,
    }
    receipts, observations = [], []

    def operate(retained, name):
        response = invoke_recorded(
            chio, connection, key + "\n", retained, directory / name
        )
        receipts.append(response["receipt_json"])
        observations.append({"request": retained, "response": response})
        return response

    with ThreadPoolExecutor(max_workers=1) as executor:
        with host.serve(chio, directory, key, environment) as process:
            invocation = executor.submit(operate, request, "original")
            committed = wait_for(fault / "committed.json", invocation=invocation)
            assert committed["response_forwarded"] is False
            process.kill()
            assert process.wait(timeout=10) == -signal.SIGKILL
        try:
            invocation.result(timeout=15)
        except WorkerError as error:
            transport_error = error.code
        else:
            raise AssertionError(
                "the original invocation unexpectedly returned an outcome"
            )
    stopped = wait_for(fault / "stopped.json")
    assert stopped == {"host_pipe_closed": True, "gateway_exit_code": 0}
    unresolved = json.loads((directory / "original" / "unresolved.json").read_text())
    assert unresolved == {
        "error": transport_error,
        "completed_response": False,
        "automatic_retry": False,
    }
    assert not (directory / "original" / "response.json").exists()
    assert not (directory / "original" / "receipts.ndjson").exists()
    retained = json.loads((directory / "original" / "request.json").read_text())
    assert retained == request
    socket_path = directory / "recovery.sock"
    resumed_path = directory / "root" / "connection-resumed.json"
    host.command(
        [
            chio,
            "process",
            "credential",
            "--state",
            directory / "host",
            "--process",
            "root",
            "--socket",
            socket_path,
            "--out",
            resumed_path,
        ],
        directory,
    )
    connection = json.loads(resumed_path.read_text())
    assert connection["credential"] != original_connection["credential"]
    assert (
        connection["caller_capability_sha256"]
        == original_connection["caller_capability_sha256"]
    )

    def inspect(job, phase):
        return value(
            operate(
                {
                    "operation_key": f"inspect-{phase}-{job}",
                    "server_id": "jobs-admin",
                    "tool_name": "inspect",
                    "arguments": {"job_id": job},
                },
                f"inspect-{phase}-{job}",
            )
        )

    with host.serve(chio, directory, key, environment, socket_path=socket_path):
        before = [inspect(job, "before") for job in jobs]
        withheld = committed["response"]["result"]["structuredContent"]["jobs"][0]
        claimed = next(job for job in before if job["job_id"] == withheld["job_id"])
        pending = next(job for job in before if job["job_id"] != withheld["job_id"])
        assert claimed == withheld
        assert claimed["state"] == "leased" and claimed["lease_fence"] == 1
        assert (
            claimed["owner_capability_sha256"]
            == request["arguments"]["owner_capability_sha256"]
        )
        assert pending["state"] == "pending" and pending["lease_fence"] == 0
        recovery_ids = []
        for attempt in range(2):
            response = operate(retained, f"recovery-{attempt}")
            receipt = json.loads(response["receipt_json"])
            recovery_ids.append(response["request_id"])
            assert response["verdict"] == "deny" and response["output"] is None
            assert (
                receipt["metadata"]["admission_operation"]["retained_state"]
                == "outcome_unknown_after_dispatch"
            )
            assert (
                receipt["metadata"]["chio_process"]["recovery_policy"]
                == "known_outcome_only"
            )
            assert (
                receipt["metadata"]["chio_process"]["operation_key"]
                == retained["operation_key"]
            )
        assert len(set(recovery_ids)) == 1
        after = [inspect(job, "after") for job in jobs]
        assert before == after
        deliveries = [
            json.loads(path.read_text()) for path in fault.glob("delivery-*.json")
        ]
        assert deliveries == [
            {
                "arguments": request["arguments"],
                "caller": connection["caller_capability_sha256"],
            }
        ]
        # This is deliberately new work, not a retry of the uncertain claim.
        # If the pending job were not claimable, a broken recovery path could
        # appear safe merely because there was no second effect to observe.
        control = value(
            operate(
                {**request, "operation_key": "explicit-new-intent-control"}, "control"
            )
        )
        assert len(control["jobs"]) == 1
        assert control["jobs"][0]["job_id"] == pending["job_id"]
        assert control["jobs"][0]["lease_fence"] == 1
        final = [inspect(job, "final") for job in jobs]
        assert all(
            job["state"] == "leased" and job["lease_fence"] == 1 for job in final
        )
        assert len(list(fault.glob("delivery-*.json"))) == 2
    host.verify(chio, directory, receipts)
    host.write(
        directory / "qualification.json",
        {
            "schema": "chio.postgres-job.claim-loss-qualification.v1",
            "evidence_kind": "scripted_native_postgres_committed_claim_response_loss",
            "live_model": False,
            "tenant": tenant,
            "chio_sha256": hashlib.sha256(chio.read_bytes()).hexdigest(),
            "gateway_sha256": gateway_hash,
            "request": retained,
            "withheld_gateway_response": committed,
            "unresolved": unresolved,
            "host_sigkill": True,
            "fresh_socket_and_rotated_credential": True,
            "caller_and_signer_unchanged": True,
            "proxy_shutdown": stopped,
            "before_recovery": before,
            "after_recovery": after,
            "after_new_intent_control": final,
            "claim_deliveries_after_recovery": 1,
            "claim_deliveries_after_control": 2,
            "original_claim_deliveries": deliveries,
            "recovery_request_ids": recovery_ids,
            "observations": observations,
            "all_exported_receipts_verified": True,
            "original_claim_receipt_recovered": False,
        },
    )
    print(
        json.dumps({"qualified": True, "report": str(directory / "qualification.json")})
    )


if __name__ == "__main__":
    main()

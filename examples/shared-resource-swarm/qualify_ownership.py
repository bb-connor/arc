"""Qualify caller forwarding, assignment fencing and receipt replay through stdio."""

import argparse
import json
import os
import sys
from pathlib import Path

import assignment
import handoff
import run
import store
from chio_process import ProcessClient
from chio_process.invocation import invoke_recorded
from mcp_client import McpClient
from test_handoff import replacement

HERE = Path(__file__).resolve().parent


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(mode=0o700)
    for name in run.ROLES:
        (directory / name).mkdir(mode=0o700)
    seed, revised = handoff.inputs()
    store.initialize(directory / "resource.db", seed)
    binary, key = run.prepare_host(args, directory, operator=True)
    connections = {
        name: json.loads((directory / name / "connection.json").read_text())
        for name in run.ROLES
    }
    callers = {name: c["caller_capability_sha256"] for name, c in connections.items()}
    assert len(set(callers.values())) == 2
    receipts = []
    with run.host(binary, key, directory):
        assignment.assign(
            binary,
            directory,
            "initial",
            "release-board",
            None,
            callers["compatibility"],
            0,
        )
        clients = {
            name: ProcessClient(c["socket_path"], c["credential"])
            for name, c in connections.items()
        }

        def invoke(who, operation, tool, arguments):
            result = clients[who].invoke(operation, "board", tool, arguments)
            receipts.append(result["receipt_json"])
            return result

        args0 = replacement("ready", "search-2", 0)
        first = invoke("compatibility", "original", "replace", args0)
        assert first["output"]["value"]["structuredContent"]["status"] == "committed"
        assignment.assign(
            binary,
            directory,
            "handoff",
            "release-board",
            0,
            callers["performance"],
            0,
            revised,
        )
        snapshot = invoke(
            "compatibility", "fresh-read", "snapshot", {"document": "release-board"}
        )
        version = snapshot["output"]["value"]["structuredContent"]["version"]
        refused = invoke(
            "compatibility",
            "fresh-write",
            "replace",
            replacement("ready", "search-2", version),
        )
        assert refused["output"]["value"]["structuredContent"] == {
            "status": "superseded",
            "assignment_generation": 1,
        }
        replay = invoke("compatibility", "original", "replace", args0)
        assert replay["receipt_json"] == first["receipt_json"]
        forged = replacement("ready", "search-2", version)
        forged["_meta"] = {"chioCallerCapabilitySha256": callers["performance"]}
        denied = invoke("compatibility", "forged-identity", "replace", forged)
        assert (
            denied["verdict"] != "allow"
            or denied["output"]["value"].get("isError") is True
        )
        current = invoke(
            "performance",
            "replacement",
            "replace",
            replacement("blocked", "search-3", version),
        )
        assert current["output"]["value"]["structuredContent"]["status"] == "committed"
        requested = assignment.evidence(directory)[0]["request"]
        escalation = clients["compatibility"].invoke(
            "cannot-assign", "board-admin", "assign", requested["arguments"]
        )
        assert escalation["verdict"] == "deny"
        receipts.append(escalation["receipt_json"])
        restricted = directory / "restricted-operator"
        restricted.mkdir(mode=0o700)
        (restricted / "root").mkdir(mode=0o700)
        run.write(restricted / "root" / "connection.json", connections["compatibility"])
        (restricted / "kernel.pub").write_text(key + "\n")
        try:
            assignment.assign(
                binary,
                restricted,
                "cannot-assign",
                "release-board",
                1,
                callers["compatibility"],
                1,
            )
        except RuntimeError as error:
            assert str(error) == "operator assignment was refused"
        else:
            raise AssertionError("operator helper accepted a child capability")
        denied_record = json.loads(
            (restricted / "operator-cannot-assign" / "response.json").read_text()
        )
        assert denied_record["verdict"] == "deny"
        receipts.append(denied_record["receipt_json"])
    operator_calls = assignment.evidence(directory)
    root = json.loads((directory / "root" / "connection.json").read_text())
    with run.host(binary, key, directory):
        for index, call in enumerate(operator_calls):
            recovered = invoke_recorded(
                binary,
                root,
                key + "\n",
                call["request"],
                directory / f"operator-recovery-{index}",
            )
            assert recovered["receipt_json"] == call["response"]["receipt_json"]
            receipts.append(recovered["receipt_json"])
        call = operator_calls[0]
        request_path = directory / "cli-request.json"
        run.write(request_path, call["request"])
        run.command(
            [
                sys.executable,
                "-m",
                "chio_process.invocation",
                "--chio",
                binary,
                "--connection",
                directory / "root" / "connection.json",
                "--trusted-kernel-pubkey",
                directory / "kernel.pub",
                "--request",
                request_path,
                "--output",
                directory / "cli-recovery",
            ],
            directory,
        )
        assert (
            json.loads((directory / "cli-recovery" / "response.json").read_text())[
                "receipt_json"
            ]
            == call["response"]["receipt_json"]
        )
        try:
            invoke_recorded(
                binary,
                root,
                "0" * 64 + "\n",
                call["request"],
                directory / "wrong-verifier-key",
            )
        except RuntimeError as error:
            assert "did not verify" in str(error)
        else:
            raise AssertionError("wrong trusted verifier key was accepted")
    snapshot = store.inspect(directory / "resource.db")
    assert handoff.assess_current(snapshot)["accepted"]
    assert len(snapshot["mutations"]) == 2
    assigned = [o for o in snapshot["operations"] if o["request"]["name"] == "assign"]
    assert len(assigned) == 2 and all(o["deliveries"] == 1 for o in assigned)
    assert len(snapshot["assignments"]) == 2 and len(snapshot["task_revisions"]) == 2
    by_id = {o["id"]: o for o in snapshot["operations"]}
    original_operation = snapshot["mutations"][0]["operation_id"]
    assert by_id[original_operation]["deliveries"] == 1
    assert (
        by_id[original_operation]["request"]["caller_capability_sha256"]
        == callers["compatibility"]
    )
    replacement_operation = snapshot["mutations"][1]["operation_id"]
    assert (
        by_id[replacement_operation]["request"]["caller_capability_sha256"]
        == callers["performance"]
    )
    with McpClient(
        [
            sys.executable,
            str(HERE / "server.py"),
            "--database",
            str(directory / "resource.db"),
        ]
    ) as unauthenticated:
        try:
            unauthenticated.invoke(
                "missing-caller", "replace", replacement("ready", "search-2", 2)
            )
        except RuntimeError as error:
            assert str(error) == "resource request refused"
        else:
            raise AssertionError("resource accepted a missing caller binding")
    assert (
        store.inspect(directory / "resource.db")["mutations"] == snapshot["mutations"]
    )
    (directory / "receipts.ndjson").write_text(
        "\n".join(dict.fromkeys(receipts)) + "\n"
    )
    run.command(
        [
            binary,
            "receipt",
            "verify",
            "--input",
            directory / "receipts.ndjson",
            "--trusted-kernel-pubkey",
            directory / "kernel.pub",
        ],
        directory,
    )
    evidence = {
        "evidence_kind": "scripted_native_resource_ownership",
        "live_model": False,
        "original_receipt_recovered_and_verified": True,
        "superseded_write_refused": True,
        "missing_caller_refused": True,
        "model_argument_identity_spoof_refused": True,
        "operator_calls": operator_calls,
        "operator_original_receipts_recovered_after_host_restart": True,
        "worker_assignment_route_refused": True,
        "operator_helper_preserves_signed_denial": True,
        "installed_operator_cli_recovered_original_receipt": True,
        "wrong_trusted_verifier_key_refused": True,
        "resource": snapshot,
    }
    run.write(directory / "qualification.json", evidence)
    print(store.encoded({"qualified": True, "resource_mutations": 2}))


if __name__ == "__main__":
    main()

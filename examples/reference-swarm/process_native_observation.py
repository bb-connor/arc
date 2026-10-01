"""Retain original confined launches before killing their observing host.

The recovered caller receipt can observe a replacement connection. It cannot
serve as the original launch reference for a tool whose return was lost.
PID linkage and death remain explicit external observations, not signed exits.
"""

import hashlib
import json
import sqlite3
from pathlib import Path

from process_qualification import write


def retain_original_launches(harness, target_pids):
    folder = harness.output / "original-native-launches"
    folder.mkdir(mode=0o700)
    target_digest = hashlib.sha256(harness.probe.read_bytes()).hexdigest()
    retained = {}
    observed_pids = set()
    for server in harness.servers:
        name = server["id"]
        policy_path = Path(server["launch_policy"])
        policy = json.loads(policy_path.read_text())
        database = Path(policy["body"]["receipt"]["database_path"])
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as db:
            matches = []
            for (raw,) in db.execute("SELECT raw_json FROM chio_tool_receipts ORDER BY seq"):
                receipt = json.loads(raw)
                body = receipt["metadata"]["cage_receipt"]
                if body["stage"] != "enforcement":
                    continue
                record = body["enforcement_record"]
                if record["state"] != "fully_enforced":
                    continue
                prepared = record["fully_enforced"]["prepared"]
                if prepared["process_id"] in target_pids:
                    matches.append((receipt, body, prepared))
        assert len(matches) == 1, (name, "expected one launch for a live pinned target")
        receipt, body, prepared = matches[0]
        pid = prepared["process_id"]
        assert pid not in observed_pids, "one target was attributed to multiple servers"
        observed_pids.add(pid)
        assert body["bindings"]["target_binding_digest"] == target_digest
        assert prepared["target_binding_digest"] == target_digest
        for field in ["landlock_filesystem_status", "landlock_network_status", "seccomp_status"]:
            assert prepared[field] == "fully_enforced", (name, field, prepared[field])
        transition = body["enforcement_record"]["fully_enforced"]["exec_transition"]
        assert transition["process_id"] == pid
        assert transition["trace_session_digest"] == prepared["trace_session_digest"]
        assert transition["target_binding_digest"] == target_digest
        # The owning host installed this exact policy; retain its bytes separately
        # from the signed receipt so a later verifier can check the full binding.
        (folder / f"{name}-policy.json").write_bytes(policy_path.read_bytes())
        (folder / f"{name}-receipt.ndjson").write_text(json.dumps(receipt) + "\n")
        (folder / f"{name}-receipt.pub").write_text(
            policy["body"]["receipt"]["trusted_signer_public_key"]
        )
        retained[name] = {
            "process_id": pid, "receipt_id": receipt["id"],
            "attempt_id": body["attempt_id"], "target_sha256": target_digest,
            "receipt_signer": policy["body"]["receipt"]["trusted_signer_public_key"],
            "policy_signer": server["launch_policy_signer"],
            "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
            "trace_session_digest": prepared["trace_session_digest"],
        }
    assert observed_pids == set(target_pids), (observed_pids, target_pids)
    write(folder / "observation.json", {
        "schema": "chio.reference-swarm.original-launch-observation.v1",
        "external_pid_observation": True, "launches": retained,
        "terminal_receipts_invented": False,
    })
    return retained


def verify_original_launch_signatures(harness, retained):
    folder = harness.output / "original-native-launches"
    for name in retained:
        harness.run("verify-original-launch-" + name, [
            harness.chio, "--json", "receipt", "verify",
            "--input", folder / f"{name}-receipt.ndjson",
            "--trusted-kernel-pubkey", folder / f"{name}-receipt.pub",
        ])

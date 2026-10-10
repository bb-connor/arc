#!/usr/bin/env python3
"""Mutate the actual Rust-emitted artifact, never a handcrafted success trace."""
import argparse
import copy
import importlib.util
import hashlib
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from formal.durable_lifecycle import canonical_fixture, validate_durable_trace
spec = importlib.util.spec_from_file_location("lifecycle", Path(__file__).resolve().parents[1] / "check-response-lifecycle.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def validate(value):
    return validate_durable_trace(value, checker.validate_runtime_trace)


class DurableEvidenceTests(unittest.TestCase):
    def test_real_evidence_and_refusal_controls(self):
        self.assertEqual(set(validate(TRACE)), {"happy", "effect_ack_loss", "receipt_ack_loss"})
        for mutant in ["missing_commit", "reorder_commit", "missing_receipt", "invalid_signature", "cross_action",
                       "result_mismatch", "early_effect", "false_completion", "duplicate_command", "missing_restart",
                       "substituted_recovery", "unknown_schema", "unknown_field", "reordered_receipt", "missing_command", "substituted_command", "intermediate_hash", "command_fence", "command_owner", "command_expiry", "command_kind", "command_id", "missing_snapshot", "snapshot_prefix"]:
            document = copy.deepcopy(TRACE)
            trace = document["scenarios"]["happy"]
            events = trace["events"]
            commits = [i for i, e in enumerate(events) if e["boundary"] == "response_commit"]
            effects = [i for i, e in enumerate(events) if e["boundary"] == "effect_commit"]
            if mutant == "missing_commit": del events[commits[1]]
            elif mutant == "reorder_commit": events[commits[1]], events[commits[2]] = events[commits[2]], events[commits[1]]
            elif mutant == "missing_receipt": trace["receipts"].pop(next(iter(trace["receipts"])))
            elif mutant == "invalid_signature": next(iter(trace["receipts"].values()))["signature"] = "00" * 64
            elif mutant == "cross_action": events[commits[0]]["action_id"] = "other-action"
            elif mutant == "result_mismatch": events[effects[0]]["resulting_version_hash"] = "00" * 32
            elif mutant == "early_effect": events.insert(0, events.pop(effects[0]))
            elif mutant == "false_completion": events[commits[-1]]["state"] = "active"
            elif mutant == "duplicate_command": trace["commands"].append(copy.deepcopy(trace["commands"][0]))
            elif mutant == "missing_restart": trace["events"] = [e for e in events if e["boundary"] != "restart"]
            elif mutant == "substituted_recovery": document["scenarios"]["effect_ack_loss"] = copy.deepcopy(trace)
            elif mutant == "unknown_schema": document["schema"] = "unknown"
            elif mutant == "unknown_field": events[0]["unexpected"] = True
            elif mutant == "reordered_receipt":
                receipt_indexes = [i for i, e in enumerate(events) if e["boundary"] == "receipt_persisted"]
                a, b = receipt_indexes[:2]
                events[a], events[b] = events[b], events[a]
            elif mutant == "missing_command": trace["commands"].pop()
            elif mutant == "substituted_command": trace["commands"][0]["request"]["target"]["session_id"] = "other-session"
            elif mutant == "intermediate_hash": events[commits[0]]["body_hash"] = "00" * 32
            elif mutant == "command_fence": trace["commands"][0]["request"]["scheduler_fencing_token"] = 999
            elif mutant == "command_owner": trace["commands"][0]["request"]["scheduler_lease_owner_id"] = "other-owner"
            elif mutant == "command_expiry": trace["commands"][0]["request"]["plan_expires_at_unix_ms"] = 0
            elif mutant == "command_kind": trace["commands"][0]["request"]["effect_kind"] = "quarantine"
            elif mutant == "missing_snapshot": trace["committed_snapshots"].pop(next(iter(trace["committed_snapshots"])))
            elif mutant == "snapshot_prefix":
                first = events[commits[0]]
                key = str(first["generation"])
                snapshot = json.loads(bytes.fromhex(trace["committed_snapshots"][key]))
                snapshot["mutations"][0]["record"]["transition_id"] = "substituted-prefix"
                raw = canonical_fixture(snapshot)
                trace["committed_snapshots"][key] = raw.hex()
                first["body_hash"] = hashlib.sha256(raw).hexdigest()
            elif mutant == "command_id":
                for command in trace["commands"]: command["request"]["idempotency_key"] = "fabricated"
                for i in effects: events[i]["idempotency_key"] = "fabricated"

            with self.subTest(mutant=mutant), self.assertRaises(ValueError):
                validate(document)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trace", required=True, type=Path)
    args = parser.parse_args()
    TRACE = json.loads(args.trace.read_text())
    unittest.main(argv=[sys.argv[0]])

#!/usr/bin/env python3
"""Calibrate committed-trace refusal with reordered and false completion claims."""
import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "response_lifecycle", Path(__file__).resolve().parents[1] / "check-response-lifecycle.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def trace():
    rows = [
        ("requested", {}),
        ("transition", {"from_state": "planned", "to_state": "applying"}),
        ("effect_requested", {"effect_id": "effect-1"}),
        ("effect_applied", {"effect_id": "effect-1"}),
        ("transition", {"from_state": "applying", "to_state": "active"}),
        ("transition", {"from_state": "active", "to_state": "rolling_back"}),
        ("rollback", {"effect_id": "effect-1", "outcome": {"outcome": "requested"}}),
        ("rollback", {"effect_id": "effect-1", "outcome": {"outcome": "restored"}}),
        ("final", {"from_state": "rolling_back", "final_state": "lifted"}),
    ]
    return {
        "mode": "live", "generation": len(rows) - 1,
        "states": ["planned", "applying", "active", "rolling_back", "lifted"],
        "mutations": [{"record_type": kind, "record": dict(record, generation=i)}
                      for i, (kind, record) in enumerate(rows)],
    }


class TraceContract(unittest.TestCase):
    def test_committed_order_and_clean_lift_require_their_evidence(self):
        valid = trace()
        self.assertIn("lifted", checker.validate_runtime_trace(valid))
        reordered = copy.deepcopy(valid)
        reordered["mutations"][2], reordered["mutations"][3] = (
            reordered["mutations"][3], reordered["mutations"][2])
        with self.assertRaisesRegex(ValueError, "out of order"):
            checker.validate_runtime_trace(reordered)
        false_lift = copy.deepcopy(valid)
        false_lift["mutations"][7]["record"]["outcome"]["outcome"] = "failed"
        with self.assertRaisesRegex(ValueError, "before restoration"):
            checker.validate_runtime_trace(false_lift)
        unrequested = copy.deepcopy(valid)
        del unrequested["mutations"][2]
        unrequested["generation"] -= 1
        for i, mutation in enumerate(unrequested["mutations"]):
            mutation["record"]["generation"] = i
        with self.assertRaisesRegex(ValueError, "without request"):
            checker.validate_runtime_trace(unrequested)


if __name__ == "__main__":
    unittest.main()

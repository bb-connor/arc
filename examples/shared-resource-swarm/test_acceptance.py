"""Negative controls for task acceptance and live-workload evidence."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import run
import store
from assess import assess

HERE = Path(__file__).resolve().parent


def board():
    return {
        "assessments": {
            service: {
                "decision": decision,
                "evidence_ids": [service + "-2"],
                "reason": "Evidence",
            }
            for service, decision in (
                ("api", "blocked"),
                ("search", "ready"),
                ("worker", "blocked"),
            )
        }
    }


class AcceptanceTests(unittest.TestCase):
    def test_wrong_decisions_and_invented_evidence_are_not_accepted(self):
        snapshot = {"documents": {"release-board": {"value": board()}}}
        self.assertTrue(assess(snapshot)["accepted"])
        for field, value in (
            ("decision", "ready"),
            ("evidence_ids", ["invented"]),
            ("reason", ""),
        ):
            invalid = copy.deepcopy(snapshot)
            invalid["documents"]["release-board"]["value"]["assessments"]["api"][
                field
            ] = value
            self.assertFalse(assess(invalid)["accepted"])
        del snapshot["documents"]["release-board"]["value"]["assessments"]["worker"]
        self.assertFalse(assess(snapshot)["accepted"])

    def test_correct_scripted_output_does_not_satisfy_live_baseline(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            db = directory / "resource.db"
            store.initialize(db, json.loads((HERE / "seed.json").read_text()))
            store.execute(
                db,
                "fixture-write",
                "replace",
                {"document": "release-board", "expected_version": 0, "value": board()},
            )
            for name in run.ROLES:
                (directory / name).mkdir()
                run.write(
                    directory / name / "result.json",
                    {
                        "graph_finished": True,
                        "tools": [],
                        "model_calls": [
                            {
                                "kind": "scripted_test",
                                "complete": True,
                                "response": {"id": "fixture"},
                            }
                        ],
                    },
                )
            report = run.report(
                SimpleNamespace(backend="baseline", model="fixture", provider="openai"),
                directory,
                {name: 0 for name in run.ROLES},
            )
            self.assertTrue(report["task"]["accepted"])
            self.assertFalse(report["live_inference_completed"])
            self.assertFalse(report["accepted"])


if __name__ == "__main__":
    unittest.main()

"""Input history and negative controls for the live handoff measurement."""

import copy
import tempfile
import unittest
from pathlib import Path

import handoff
import store


def replacement(decision, evidence, version):
    return {
        "document": "release-board",
        "expected_version": version,
        "value": {
            "assessments": {
                "search": {
                    "decision": decision,
                    "evidence_ids": [evidence],
                    "reason": "Measurement",
                }
            }
        },
    }


class HandoffTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / "resource.db"
        self.seed, self.revised = handoff.inputs()
        store.initialize(self.database, self.seed)

    def test_revision_publication_preserves_seed_and_original_read_replay(self):
        original = store.execute(self.database, "old-task", "task", {})
        self.assertEqual(store.revise_task(self.database, 0, self.revised), 1)
        with self.assertRaisesRegex(ValueError, "task revision conflict"):
            store.revise_task(self.database, 0, self.seed["task"])
        current = store.execute(self.database, "new-task", "task", {})
        self.assertEqual(current["task_revision"], 1)
        self.assertEqual(current["task"], self.revised)
        self.assertNotEqual(current["task_sha256"], original["task_sha256"])
        self.assertEqual(current["seed_sha256"], original["seed_sha256"])
        self.assertEqual(store.execute(self.database, "old-task", "task", {}), original)
        history = store.inspect(self.database)["task_revisions"]
        self.assertEqual(
            [r["task"] for r in history], [self.seed["task"], self.revised]
        )
        with self.assertRaisesRegex(ValueError, "unknown tool"):
            store.execute(self.database, "agent-update", "revise_task", self.revised)

    def test_corrected_assessment_is_lost_despite_current_version_check(self):
        store.revise_task(self.database, 0, self.revised)
        store.execute(
            self.database,
            "replacement",
            "replace",
            replacement("blocked", "search-3", 0),
        )
        after = store.inspect(self.database)
        self.assertTrue(handoff.assess_current(after)["accepted"])
        rejected = store.execute(
            self.database,
            "stale-version",
            "replace",
            replacement("ready", "search-2", 0),
        )
        self.assertEqual(rejected["status"], "version_conflict")
        version = store.execute(
            self.database, "fresh-read", "snapshot", {"document": "release-board"}
        )["version"]
        store.execute(
            self.database,
            "old-new-operation",
            "replace",
            replacement("ready", "search-2", version),
        )
        snapshot = store.inspect(self.database)
        report = {
            "backend": "baseline",
            "framework": "scripted_control",
            "resource": snapshot,
            "task": handoff.assess_current(snapshot),
            "live_inference_completed": False,
            "receipts_verified": False,
        }
        measurement = handoff.measurements(report, after)
        self.assertEqual(measurement["superseded_worker_mutations"], 1)
        self.assertEqual(measurement["superseded_operations"], ["old-new-operation"])
        self.assertFalse(measurement["final_task_accepted"])
        self.assertFalse(measurement["live_inference_completed"])

    def test_acceptance_requires_current_decisive_evidence(self):
        store.execute(
            self.database, "correct", "replace", replacement("blocked", "search-3", 0)
        )
        snapshot = store.inspect(self.database)
        for field, value in (
            ("decision", "ready"),
            ("evidence_ids", ["search-2"]),
            ("evidence_ids", ["search-3", "invented"]),
            ("evidence_ids", [{}]),
            ("reason", ""),
        ):
            invalid = copy.deepcopy(snapshot)
            invalid["documents"]["release-board"]["value"]["assessments"]["search"][
                field
            ] = value
            self.assertFalse(handoff.assess_current(invalid)["accepted"])


if __name__ == "__main__":
    unittest.main()

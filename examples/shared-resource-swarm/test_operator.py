"""Assignment tools keep publication, caller binding and outcomes atomic."""

import concurrent.futures
import tempfile
import unittest
from pathlib import Path

import handoff
import server
import store
from test_handoff import replacement
from test_resource import request

ROOT, OLD, NEW = "c" * 64, "a" * 64, "b" * 64


class OperatorTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.database = Path(directory.name) / "resource.db"
        seed, self.revised = handoff.inputs()
        store.initialize(self.database, seed)
        self.initial = {
            "document": "release-board",
            "expected_generation": None,
            "owner_capability_sha256": OLD,
            "expected_revision": 0,
            "task": None,
        }

    def invoke(self, key, args, caller=ROOT):
        return store.execute(self.database, key, "assign", args, caller, operator=True)

    def test_assignment_replay_cannot_move_owner_back_or_change_caller(self):
        first = self.invoke("initial", self.initial)
        move = {
            **self.initial,
            "expected_generation": 0,
            "owner_capability_sha256": NEW,
            "task": self.revised,
        }
        self.assertEqual(
            self.invoke("move", move),
            {"status": "assigned", "generation": 1, "task_revision": 1},
        )
        self.assertEqual(self.invoke("initial", self.initial), first)
        with self.assertRaisesRegex(ValueError, "operation identity conflict"):
            self.invoke("initial", self.initial, caller=OLD)
        with self.assertRaisesRegex(ValueError, "operation identity conflict"):
            self.invoke("move", {**move, "task": {}})
        snapshot = store.inspect(self.database)
        self.assertEqual(len(snapshot["assignments"]), 2)
        self.assertEqual(snapshot["assignments"][-1]["caller_capability_sha256"], NEW)
        self.assertEqual(len(snapshot["task_revisions"]), 2)

    def test_operator_mode_and_kernel_caller_are_required(self):
        for operator, caller in [(False, ROOT), (True, None)]:
            response = server.respond(
                self.database,
                request(
                    "invalid",
                    "assign",
                    self.initial,
                    metadata={"chioCallerCapabilitySha256": caller},
                ),
                operator=operator,
            )
            self.assertTrue(response["result"]["isError"])
        for field in ("_meta", "caller_capability_sha256"):
            with self.assertRaisesRegex(ValueError, "incorrect argument"):
                self.invoke("spoof", {**self.initial, field: ROOT})
        self.assertEqual(store.inspect(self.database)["assignments"], [])
        self.assertEqual(store.inspect(self.database)["operations"], [])

    def test_conflicts_replay_without_partial_input_publication(self):
        self.invoke("initial", self.initial)
        bad = {
            **self.initial,
            "expected_generation": 0,
            "expected_revision": 99,
            "owner_capability_sha256": NEW,
            "task": self.revised,
        }
        refused = self.invoke("bad-revision", bad)
        self.assertEqual(
            refused, {"status": "task_revision_conflict", "task_revision": 0}
        )
        snapshot = store.inspect(self.database)
        self.assertEqual(len(snapshot["task_revisions"]), 1)
        self.assertEqual(len(snapshot["assignments"]), 1)
        self.invoke("move", {**bad, "expected_revision": 0})
        self.assertEqual(self.invoke("bad-revision", bad), refused)

    def test_operator_assignment_serializes_with_old_worker_mutation(self):
        self.invoke("initial", self.initial)
        move = {
            **self.initial,
            "expected_generation": 0,
            "owner_capability_sha256": NEW,
            "task": self.revised,
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            write = executor.submit(
                store.execute,
                self.database,
                "racing-write",
                "replace",
                replacement("ready", "search-2", 0),
                OLD,
            )
            assign = executor.submit(self.invoke, "move", move)
            first, moved = write.result(timeout=10), assign.result(timeout=10)
        self.assertEqual(moved["generation"], 1)
        self.assertIn(first["status"], ("committed", "superseded"))
        version = store.inspect(self.database)["documents"]["release-board"]["version"]
        self.assertEqual(
            store.execute(
                self.database,
                "later-write",
                "replace",
                replacement("ready", "search-2", version),
                OLD,
            )["status"],
            "superseded",
        )
        self.assertEqual(
            store.execute(
                self.database,
                "new-owner-write",
                "replace",
                replacement("blocked", "search-3", version),
                NEW,
            )["status"],
            "committed",
        )


if __name__ == "__main__":
    unittest.main()

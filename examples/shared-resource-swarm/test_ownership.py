"""Atomic resource ownership, identity binding and replay controls."""

import concurrent.futures
import tempfile
import unittest
from pathlib import Path

import handoff
import server
import store
from test_handoff import replacement
from test_resource import request

OLD, NEW = "a" * 64, "b" * 64


class OwnershipTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.database = Path(temporary.name) / "resource.db"
        seed, self.revised = handoff.inputs()
        store.initialize(self.database, seed)
        store.assign_work(self.database, "release-board", None, OLD, 0)

    def move(self):
        return store.assign_work(
            self.database, "release-board", 0, NEW, 0, self.revised
        )

    def replace(self, key, caller, version):
        return store.execute(
            self.database,
            key,
            "replace",
            replacement("ready", "search-2", version),
            caller,
        )

    def test_handoff_blocks_fresh_old_owner_writes_but_preserves_prior_outcomes(self):
        original = self.replace("old-effect", OLD, 0)
        self.move()
        self.assertEqual(self.replace("old-effect", OLD, 0), original)
        with self.assertRaisesRegex(ValueError, "operation identity conflict"):
            self.replace("old-effect", NEW, 0)
        version = store.execute(
            self.database, "fresh", "snapshot", {"document": "release-board"}, OLD
        )["version"]
        self.assertEqual(
            self.replace("superseded", OLD, version),
            {"status": "superseded", "assignment_generation": 1},
        )
        self.assertEqual(
            self.replace("replacement", NEW, version)["status"], "committed"
        )
        self.assertEqual(len(store.inspect(self.database)["mutations"]), 2)

    def test_missing_binding_and_model_argument_spoofing_cannot_write(self):
        with self.assertRaisesRegex(ValueError, "authenticated caller"):
            self.replace("missing", None, 0)
        args = replacement("ready", "search-2", 0)
        args["chioCallerCapabilitySha256"] = OLD
        forged = server.respond(self.database, request("forged", "replace", args))
        self.assertTrue(forged["result"]["isError"])
        # An established baseline pipe selects its own caller even if another
        # identity is supplied in MCP metadata.
        metadata = {"chioCallerCapabilitySha256": OLD}
        result = server.respond(
            self.database,
            request(
                "wrong-pipe",
                "replace",
                replacement("ready", "search-2", 0),
                metadata=metadata,
            ),
            NEW,
        )
        self.assertEqual(result["result"]["structuredContent"]["status"], "superseded")
        self.assertEqual(store.inspect(self.database)["mutations"], [])

    def test_failed_handoff_does_not_publish_partial_input_or_assignment(self):
        with self.assertRaisesRegex(ValueError, "task revision conflict"):
            store.assign_work(self.database, "release-board", 0, NEW, 99, self.revised)
        with self.assertRaisesRegex(ValueError, "assignment generation conflict"):
            store.assign_work(
                self.database, "release-board", None, NEW, 0, self.revised
            )
        snapshot = store.inspect(self.database)
        self.assertEqual(len(snapshot["task_revisions"]), 1)
        self.assertEqual(len(snapshot["assignments"]), 1)
        self.assertEqual(self.replace("still-owner", OLD, 0)["status"], "committed")

    def test_reassignment_and_write_serialize_and_no_later_old_write_commits(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            write = pool.submit(self.replace, "racing-old", OLD, 0)
            move = pool.submit(self.move)
            first = write.result(timeout=10)
            self.assertEqual(move.result(timeout=10)["generation"], 1)
        self.assertIn(first["status"], ("committed", "superseded"))
        snapshot = store.inspect(self.database)
        version = snapshot["documents"]["release-board"]["version"]
        self.assertEqual(version, int(first["status"] == "committed"))
        self.assertEqual(
            self.replace("old-after-move", OLD, version)["status"], "superseded"
        )
        self.assertEqual(
            self.replace("new-after-move", NEW, version)["status"], "committed"
        )

    def test_returning_owner_requires_new_operation_after_known_supersession(self):
        self.move()
        refused = self.replace("known-refusal", OLD, 0)
        store.assign_work(self.database, "release-board", 1, OLD, 1)
        self.assertEqual(self.replace("known-refusal", OLD, 0), refused)
        self.assertEqual(
            self.replace("new-assignment-operation", OLD, 0)["status"], "committed"
        )


if __name__ == "__main__":
    unittest.main()

"""Run with python3 -m unittest discover -s examples/shared-resource-swarm."""

import concurrent.futures
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import store

HERE = Path(__file__).resolve().parent


def request(key, name, arguments=None, rpc_id=1, metadata=None):
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments or {},
            "_meta": {"chioRequestId": key, **(metadata or {})},
        },
    }


def replacement(value, version=0):
    return {"document": "release-board", "expected_version": version, "value": value}


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.database = Path(self.temporary.name) / "resource.db"
        self.seed = json.loads((HERE / "seed.json").read_text())
        store.initialize(self.database, self.seed)

    def rpc(self, *requests):
        result = subprocess.run(
            [sys.executable, str(HERE / "server.py"), "--database", str(self.database)],
            input="".join(json.dumps(item) + "\n" for item in requests),
            text=True,
            capture_output=True,
            timeout=15,
            check=True,
        )
        self.assertEqual(result.stderr, "")
        return [json.loads(line) for line in result.stdout.splitlines()]

    def value(self, key, name, args=None):
        response = self.rpc(request(key, name, args))[0]["result"]
        self.assertFalse(response["isError"])
        return response["structuredContent"]

    def test_stdio_discovery_and_task_identity(self):
        responses = self.rpc(
            {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
            request("task-1", "task", rpc_id=3),
        )
        self.assertEqual([r["id"] for r in responses], [1, 2, 3])
        tools = responses[1]["result"]["tools"]
        self.assertEqual(
            {t["name"] for t in tools}, {"task", "read", "replace", "outcome"}
        )
        value = responses[2]["result"]["structuredContent"]
        self.assertEqual(value["task"], self.seed["task"])
        self.assertEqual(
            value["seed_sha256"], store.inspect(self.database)["seed_sha256"]
        )

    def test_process_death_after_commit_recovers_resource_outcome(self):
        # No response is delivered. The next server process sees only the DB.
        program = (
            "import json, os, sys, store; "
            "store.execute(sys.argv[1], 'lost-response', 'replace', json.loads(sys.argv[2])); "
            "os._exit(77)"
        )
        args = replacement({"assessments": {"api": "blocked"}})
        died = subprocess.run(
            [sys.executable, "-c", program, str(self.database), json.dumps(args)],
            cwd=HERE,
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(died.returncode, 77)
        self.assertEqual(died.stdout, b"")
        outcome = self.value("lookup-1", "outcome", {"operation_id": "lost-response"})
        self.assertEqual(outcome["status"], "known")
        self.assertEqual(outcome["request"], {"name": "replace", "arguments": args})
        replay = self.value("lost-response", "replace", args)
        self.assertEqual(replay, outcome["result"])
        state = store.inspect(self.database)
        self.assertEqual(len(state["mutations"]), 1)
        operation = next(o for o in state["operations"] if o["id"] == "lost-response")
        self.assertEqual(operation["deliveries"], 2)

    def test_competing_processes_cannot_both_commit_same_version(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    self.value, f"worker-{n}", "replace", replacement({"worker": n})
                )
                for n in range(2)
            ]
            results = [future.result(timeout=20) for future in futures]
        self.assertEqual(
            sorted(r["status"] for r in results), ["committed", "version_conflict"]
        )
        self.assertEqual(len(store.inspect(self.database)["mutations"]), 1)

    def test_changed_request_identity_is_refused_without_mutation(self):
        self.value("stable", "replace", replacement({"first": True}))
        response = self.rpc(
            request("stable", "replace", replacement({"second": True}, 1))
        )[0]
        self.assertTrue(response["result"]["isError"])
        state = store.inspect(self.database)
        self.assertEqual(state["documents"]["release-board"]["value"], {"first": True})
        self.assertEqual(len(state["mutations"]), 1)

    def test_replayed_reads_and_conflicts_retain_original_snapshot(self):
        original = self.value("read-1", "read", {"document": "release-board"})
        self.value("write-1", "replace", replacement({"worker": 1}))
        conflict = self.value("old-write", "replace", replacement({"worker": 0}))
        self.assertEqual(conflict, {"status": "version_conflict", "version": 1})
        self.value("write-2", "replace", replacement({"worker": 2}, 1))
        self.assertEqual(
            self.value("read-1", "read", {"document": "release-board"}), original
        )
        self.assertEqual(
            self.value("old-write", "replace", replacement({"worker": 0})), conflict
        )
        self.assertEqual(
            self.value("read-2", "read", {"document": "release-board"})["version"], 2
        )

    def test_unknown_lookup_requires_new_poll_identity(self):
        self.assertEqual(
            self.value("poll-1", "outcome", {"operation_id": "later"}),
            {"status": "unknown"},
        )
        self.value("later", "replace", replacement({"new": True}))
        self.assertEqual(
            self.value("poll-1", "outcome", {"operation_id": "later"}),
            {"status": "unknown"},
        )
        self.assertEqual(
            self.value("poll-2", "outcome", {"operation_id": "later"})["status"],
            "known",
        )

    def test_transport_attempt_changes_preserve_logical_identity(self):
        args = replacement({"ready": True})
        first = self.rpc(
            request("stable", "replace", args, 20, {"chioAttemptId": "attempt-1"})
        )[0]["result"]
        second = self.rpc(
            request("stable", "replace", args, 30, {"chioAttemptId": "attempt-2"})
        )[0]["result"]
        self.assertEqual(first, second)
        self.assertEqual(len(store.inspect(self.database)["mutations"]), 1)

    def test_unbound_and_malformed_mutations_refused(self):
        missing = request("unused", "replace", replacement({"no": True}))
        del missing["params"]["_meta"]
        malformed = request("boolean-version", "replace", replacement({}, True))
        wrong_fields = request(
            "model-identity",
            "replace",
            {
                **replacement({}),
                "chioRequestId": "chosen-by-model",
            },
        )
        responses = self.rpc(missing, malformed, wrong_fields)
        self.assertTrue(all(r["result"]["isError"] for r in responses))
        self.assertEqual(store.inspect(self.database)["mutations"], [])

    def test_initialization_never_resets_existing_state(self):
        self.value("write-1", "replace", replacement({"retained": True}))
        with self.assertRaises(FileExistsError):
            store.initialize(self.database, self.seed)
        self.assertEqual(
            store.inspect(self.database)["documents"]["release-board"]["version"], 1
        )
        missing = Path(self.temporary.name) / "missing.db"
        with self.assertRaises(sqlite3.OperationalError) as raised:
            store.execute(missing, "read", "task", {})
        self.assertIn("unable to open database", str(raised.exception))
        self.assertFalse(missing.exists())


if __name__ == "__main__":
    unittest.main()

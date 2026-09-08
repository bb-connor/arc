"""Framework compatibility checks, not live inference or OS graph recovery."""

import json
import tempfile
import unittest
from pathlib import Path

import graph
import langgraph_worker
import store
from langgraph.checkpoint.memory import InMemorySaver
from mcp_client import McpClient
from provider import SavedChat, UnknownModelOutcome

HERE = Path(__file__).resolve().parent


def response(turn, calls=None):
    message = {"role": "assistant", "content": "Finished." if not calls else None}
    if calls:
        message["tool_calls"] = [
            {
                "id": f"call-{turn}-{i}",
                "type": "function",
                "function": {"name": name, "arguments": store.encoded(args)},
            }
            for i, (name, args) in enumerate(calls)
        ]
    return {
        "id": f"response-{turn}",
        "model": "fixture",
        "choices": [
            {"finish_reason": "tool_calls" if calls else "stop", "message": message}
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5},
    }


class GraphTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.database = self.directory / "resource.db"
        self.seed = json.loads((HERE / "seed.json").read_text())
        store.initialize(self.database, self.seed)
        self.settings = {"thread_id": "job-1", "max_rounds": 4, "services": ["api"]}
        self.assessment = {
            "assessments": {
                "api": {
                    "decision": "blocked",
                    "evidence_ids": ["api-2"],
                    "reason": "Duplicates",
                }
            }
        }
        self.responses = [
            response(
                0,
                [
                    ("board__task", {}),
                    ("board__snapshot", {"document": "release-board"}),
                ],
            ),
            response(
                1,
                [
                    (
                        "board__replace",
                        {
                            "document": "release-board",
                            "expected_version": 0,
                            "value": self.assessment,
                        },
                    )
                ],
            ),
            response(2),
        ]
        self.requests = []

    def transport(self, request):
        self.requests.append(request)
        return self.responses[len(self.requests) - 1]

    def model(self, transport=None):
        return SavedChat(
            self.directory / "model.db",
            "fixture",
            transport=transport or self.transport,
            evidence_kind="scripted_test",
        )

    def client(self):
        import sys

        return McpClient(
            [sys.executable, str(HERE / "server.py"), "--database", str(self.database)]
        )

    def test_real_mcp_graph_and_completed_thread_recovery(self):
        saver = InMemorySaver()
        with self.client() as client:
            result = langgraph_worker.run(
                self.settings, saver, self.model(), graph.BaselineTools(client)
            )
        self.assertTrue(result["graph_finished"])
        self.assertEqual(len(self.requests), 3)
        self.assertTrue(
            all(c["kind"] == "scripted_test" for c in result["model_calls"])
        )
        self.assertEqual(
            store.inspect(self.database)["documents"]["release-board"]["value"],
            self.assessment,
        )
        self.assertEqual(len(store.inspect(self.database)["mutations"]), 1)
        with self.client() as client:
            resumed = langgraph_worker.run(
                self.settings, saver, self.model(), graph.BaselineTools(client)
            )
        self.assertEqual(resumed["tools"], result["tools"])
        self.assertEqual(len(self.requests), 3)

    def test_effect_before_graph_checkpoint_uses_original_operation(self):
        saver = InMemorySaver()
        config = {"configurable": {"thread_id": "job-1"}}

        def fail_after_replace(state, _result):
            if state["messages"][-1].tool_calls[0]["name"] == "board__replace":
                raise RuntimeError("injected checkpoint gap")

        with self.client() as client:
            app = graph.build(
                self.model(),
                graph.BaselineTools(client),
                saver,
                after_tools=fail_after_replace,
            )
            from langchain_core.messages import HumanMessage

            with self.assertRaisesRegex(RuntimeError, "injected checkpoint gap"):
                app.invoke(
                    {"messages": [HumanMessage(content="Review api", id="request")]},
                    config,
                    durability="sync",
                )
        self.assertEqual(app.get_state(config).next, ("tools",))
        self.assertEqual(len(self.requests), 2)
        before = store.inspect(self.database)
        self.assertEqual(len(before["mutations"]), 1)
        with self.client() as client:
            resumed = graph.build(self.model(), graph.BaselineTools(client), saver)
            result = resumed.invoke(None, config, durability="sync")
        self.assertEqual(result["messages"][-1].content, "Finished.")
        after = store.inspect(self.database)
        self.assertEqual(after["mutations"], before["mutations"])
        mutation_key = after["mutations"][0]["operation_id"]
        operation = next(o for o in after["operations"] if o["id"] == mutation_key)
        self.assertEqual(operation["deliveries"], 2)
        self.assertEqual(len(self.requests), 3)

    def test_model_response_survives_reconstruction_and_request_drift_refuses(self):
        model = self.model()
        original = model.invoke(
            0, [{"role": "user", "content": "Assess"}], graph.SCHEMAS
        )
        retained = self.model().invoke(
            0, [{"role": "user", "content": "Assess"}], graph.SCHEMAS
        )
        self.assertEqual(retained, original)
        self.assertEqual(len(self.requests), 1)
        with self.assertRaisesRegex(ValueError, "request or provider identity changed"):
            self.model().invoke(
                0, [{"role": "user", "content": "Different"}], graph.SCHEMAS
            )
        self.assertEqual(len(self.requests), 1)

    def test_unretained_provider_outcome_stops_without_retry(self):
        calls = []

        def lost(request):
            calls.append(request)
            raise OSError("connection lost")

        with self.assertRaises(OSError):
            self.model(lost).invoke(0, [], graph.SCHEMAS)
        with self.assertRaises(UnknownModelOutcome):
            self.model(lost).invoke(0, [], graph.SCHEMAS)
        self.assertEqual(len(calls), 1)
        self.assertIsNone(self.model().evidence()[0]["response"])
        self.assertEqual(store.inspect(self.database)["mutations"], [])

    def test_substituted_provider_cannot_claim_live_evidence(self):
        with self.assertRaisesRegex(ValueError, "substituted provider"):
            SavedChat(
                self.directory / "fake-live.db", "fixture", transport=self.transport
            )

    def test_repeated_response_identity_refuses_before_mutation(self):
        self.responses[1]["id"] = self.responses[0]["id"]
        with self.client() as client:
            with self.assertRaisesRegex(
                ValueError, "repeated an assistant response identity"
            ):
                langgraph_worker.run(
                    self.settings,
                    InMemorySaver(),
                    self.model(),
                    graph.BaselineTools(client),
                )
        self.assertEqual(store.inspect(self.database)["mutations"], [])

    def test_malformed_model_batch_refused_before_any_resource_dispatch(self):
        invalid = response(
            0,
            [
                (
                    "board__replace",
                    {"document": "release-board", "expected_version": 0, "value": {}},
                ),
                ("unconfigured_tool", {}),
            ],
        )
        model = self.model(lambda _: invalid)
        with self.client() as client:
            with self.assertRaisesRegex(ValueError, "unconfigured provider tool call"):
                langgraph_worker.run(
                    self.settings, InMemorySaver(), model, graph.BaselineTools(client)
                )
        self.assertEqual(store.inspect(self.database)["operations"], [])


if __name__ == "__main__":
    unittest.main()

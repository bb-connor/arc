"""Real framework response checks with a modeled, in-process native transport."""
from contextlib import contextmanager, redirect_stdout
import asyncio
import io
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import httpx
from langgraph.checkpoint.memory import InMemorySaver

import host_acceptance
from chio_sdk.recovery_host import RecoveryHostSession


ROOT = Path(__file__).resolve().parents[2]
REFUSAL = {"category": "refused", "error_code": "recovery.authority_denied"}


class NativeResponseScenario:
    """Committed response bytes; no native execution or provider qualification."""
    def __init__(self, revocation=None):
        corpus = json.loads((ROOT / "spec/vectors/recovery/v1/authority-contracts.json").read_text())
        self.response = json.loads(next(row["wire"] for row in corpus["vectors"]
            if row["contract"] == "command_result" and row["valid"]))
        status = self.response["status"]
        self.success = {"category": "complete", "command_id": status["command_id"],
                        "workflow_id": status["workflow_id"], "effect": "complete",
                        "control": "active", "release": "released"}
        self.command = json.dumps({"schema": "chio.recovery.command.v1", "version": 1,
            "command_id": status["command_id"], "command": {"kind": "inspect_workflow",
            "workflow_id": status["workflow_id"]}}, sort_keys=True, separators=(",", ":")).encode()
        self.revoked = False
        self.revocation = revocation or (lambda: self.revoked)
        self.requests = []

    def serve(self, request):
        self.requests.append(json.loads(request.content))
        if self.revocation():
            return httpx.Response(403, text="recovery.authority_denied")
        return httpx.Response(200, json=self.response)

    def session(self):
        return RecoveryHostSession("http://localhost:1", "synthetic-capability-canary",
            {"resume": self.command}, max_tool_actions=3, transport=httpx.MockTransport(self.serve))

    async def revoke(self):
        self.revoked = True


class HostResponseMetadataTest(unittest.TestCase):
    def assert_private_payload_absent(self, value):
        text = json.dumps(value)
        self.assertNotIn("canary", text)
        self.assertNotIn("capability", text)
        self.assertNotIn("original_response", text)
        self.assertNotIn("receipt", text)

    def assert_three_exact_requests(self, scenario, session):
        self.assertEqual(session.attempts, 3)
        self.assertEqual(len(scenario.requests), 3)
        self.assertTrue(all(row["command"].encode() == scenario.command
                            for row in scenario.requests))

    def test_graph_accepts_exact_closed_metadata_and_retains_it_in_checkpoints(self):
        scenario = NativeResponseScenario()
        session = scenario.session()
        saver = InMemorySaver()
        try:
            with patch("langgraph.checkpoint.memory.InMemorySaver", return_value=saver):
                outputs = asyncio.run(host_acceptance.graph_case(session, scenario.revoke))
        except ValueError as error:
            self.fail(f"graph fixture rejected valid native metadata: {error}")
        self.assertEqual(outputs, {"first": scenario.success, "replay": scenario.success, "revoked": REFUSAL})
        self.assert_three_exact_requests(scenario, session)
        self.assert_private_payload_absent(outputs)
        histories = list(saver.list({"configurable": {"thread_id": "public-native-acceptance"}}))
        retained = []
        for snapshot in histories:
            values = snapshot.checkpoint["channel_values"]
            self.assert_private_payload_absent(values)
            if "recovery" in values:
                self.assertIn(values["recovery"], [scenario.success, REFUSAL])
                retained.append(values["recovery"])
        self.assertIn(scenario.success, retained)
        self.assertIn(REFUSAL, retained)

    def test_real_model_free_crew_retains_completion_replay_and_exact_refusal(self):
        scenario = NativeResponseScenario()
        session = scenario.session()
        first = host_acceptance.crew_action(session)
        replay = host_acceptance.crew_action(session)
        scenario.revoked = True
        refused = host_acceptance.crew_action(session)
        self.assertEqual(first, scenario.success)
        self.assertEqual(replay, scenario.success)
        self.assertEqual(refused, REFUSAL)
        self.assert_three_exact_requests(scenario, session)
        self.assert_private_payload_absent([first, replay, refused])

    def test_main_crew_branch_accepts_closed_metadata_with_modeled_native_launch(self):
        # Actual graph_case has its own checkpoint test above. Isolate the main
        # Crew branch while keeping real SDK actions in the preceding graph slot.
        import tempfile
        scenarios = {}
        sessions = []
        real_session = RecoveryHostSession

        @contextmanager
        def native_launch(argv, **options):
            exchange = Path(options["env"]["CHIO_RECOVERY_HOST_EXCHANGE"])
            scenario = NativeResponseScenario(lambda: (exchange / "revoke").exists())
            scenarios[exchange.name] = scenario
            (exchange / "capability.json").write_text("synthetic-capability-canary")
            (exchange / "command.json").write_bytes(scenario.command)
            (exchange / "revoked").touch()
            # These are explicitly modeled fixture facts, never native evidence.
            (exchange / "native-evidence.json").write_text(json.dumps(
                {"workload_effects": 1, "effects": 2, "revoked": True}))
            def finish():
                (exchange / "finish").touch()
                return 0
            yield SimpleNamespace(process=SimpleNamespace(poll=lambda: None), log=None, finish=finish)
            self.assertTrue((exchange / "finish").is_file())

        def session_factory(*args, **options):
            session = real_session(*args, **options)
            sessions.append(session)
            return session

        async def graph_slot(session, revoked):
            first = (await session.execute("resume")).as_dict()
            replay = (await session.execute("resume")).as_dict()
            await revoked()
            refused = (await session.execute("resume")).as_dict()
            return {"first": first, "replay": replay, "revoked": refused}

        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "modeled-host-response"
            with patch.object(sys, "argv", ["host_acceptance", "--checkout", str(ROOT),
                                            "--evidence", str(evidence)]), \
                 patch.object(host_acceptance, "owned_native_process", native_launch), \
                 patch.object(host_acceptance, "wait_endpoint", return_value="http://localhost:1"), \
                 patch.object(host_acceptance, "NativeTrace",
                              lambda path: httpx.MockTransport(scenarios[path.parent.name].serve)), \
                 patch.object(host_acceptance, "graph_case", graph_slot), \
                 patch("chio_sdk.recovery_host.RecoveryHostSession", session_factory), \
                 redirect_stdout(io.StringIO()):
                try:
                    host_acceptance.main()
                except ValueError as error:
                    self.fail(f"Crew fixture rejected valid native metadata: {error}")
            result = json.loads((evidence / "result.json").read_text())
            self.assertTrue(result["passed"])
            self.assertEqual([case["framework"] for case in result["cases"]], ["langgraph", "crewai"])
            for case, session in zip(result["cases"], sessions, strict=True):
                scenario = scenarios[case["framework"]]
                self.assertEqual(case["outputs"], {
                    "first": scenario.success, "replay": scenario.success, "revoked": REFUSAL})
                self.assert_three_exact_requests(scenario, session)
                self.assert_private_payload_absent(case["outputs"])


if __name__ == "__main__":
    unittest.main()

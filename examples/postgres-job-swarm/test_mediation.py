"""Configuration refusal and original-request preservation before native CI."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from chio_process import WorkerError

import host
import invocation
from resources import OPERATIONS, server


class MediationTests(unittest.TestCase):
    def test_wrong_tenant_route_and_duplicate_operation_refuse_before_initialization(self):
        routes = [{"quota": {"server_id": server(tool), "tool_name": tool},
                   "preparation": {"payload": {"kind": "caller_bound_resource", "route": {
                       "resource": "postgres-jobs", "tenant": "one", "operation": tool}}}}
                  for tool in OPERATIONS]
        for mutation in ("tenant", "operation", "server", "duplicate", "missing"):
            changed = copy.deepcopy(routes)
            if mutation in ("tenant", "operation"):
                changed[0]["preparation"]["payload"]["route"][mutation] = "other"
            elif mutation == "server":
                changed[0]["quota"]["server_id"] = "arbitrary"
            elif mutation == "duplicate":
                changed[1] = changed[0]
            else:
                changed.pop()
            resources = SimpleNamespace(config={"native_broker": {"routes": changed}})
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                with patch.object(host, "command") as command:
                    with self.assertRaises(ValueError):
                        host.prepare(Path(__file__), Path(__file__), "one", Path(directory), {},
                                     resources=resources)
                    command.assert_not_called()
                    self.assertEqual(list(Path(directory).iterdir()), [])

    def test_uncertain_wire_invocation_keeps_logical_intent_separate(self):
        logical = {"operation_key": "original", "server_id": server("assign"),
                   "tool_name": "assign", "arguments": {"limit": 1},
                   "known_outcome_only": True}
        prepared = {"schema": "chio.broker-execute.v1", "invocation_id": "fixed"}
        connection = {"socket_path": "unused", "credential": "unused"}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "invocation"
            def lose_response(_chio, _connection, _key, request, selected):
                self.assertEqual(request, {**logical, "arguments": prepared})
                selected.mkdir()
                host.write(selected / "request.json", request)
                raise WorkerError("connection_closed")
            with patch.object(invocation.ProcessClient, "prepare_invocation", return_value=prepared) as prepare:
                with patch.object(invocation, "invoke_recorded", side_effect=lose_response) as invoke:
                    with self.assertRaises(WorkerError):
                        invocation.invoke_resource_recorded(Path(__file__), connection, "key", logical, output)
                    prepare.assert_called_once()
                    invoke.assert_called_once()
            self.assertEqual(json.loads((output / "logical-request.json").read_text()), logical)
            self.assertEqual(json.loads((output / "request.json").read_text())["arguments"], prepared)
            self.assertFalse((output / "response.json").exists())


if __name__ == "__main__":
    unittest.main()

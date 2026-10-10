"""Configuration refusal and original-request preservation before native CI."""

import copy
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from chio_process import WorkerError

import host
import invocation
from qualify import value
from resources import OPERATIONS, ResourceGateway, server


class MediationTests(unittest.TestCase):
    def test_native_value_decodes_the_kernel_projected_broker_response(self):
        application = {"status": "assigned", "jobs": [{"lease_fence": 1}]}
        # This decoder consumes application JSON, not cryptographic evidence.
        # The real recorded-invocation path separately verifies the receipt.
        broker = {
            "status": 200, "headers": [],
            "body": list(json.dumps(application).encode()),
            "evidence": {"schema": "chio.broker-execution-evidence.v2"},
            "receiptReference": "fixture", "receipt": {},
        }
        response = {"verdict": "allow", "output": {"kind": "value", "value": broker}}
        self.assertEqual(value(response), application)
        with self.assertRaisesRegex(AssertionError, "kernel denial"):
            value({**response, "verdict": "deny"})
        for invalid, code in (
            ({**broker, "status": 500}, "incomplete_broker_response"),
            ({**broker, "body": [True]}, "invalid_broker_body"),
            ({"isError": False, "structuredContent": broker}, "incomplete_broker_response"),
        ):
            with self.subTest(code=code), self.assertRaises(WorkerError) as caught:
                value({"verdict": "allow", "output": {"kind": "value", "value": invalid}})
            self.assertEqual(caught.exception.code, code)

    def test_resource_certificate_is_a_server_leaf(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(ResourceGateway, "_spawn"), patch("resources.wait_line"):
                with ResourceGateway(Path(__file__), "tenant", directory, {}) as gateway:
                    certificate = subprocess.run(
                        ["openssl", "x509", "-in", str(gateway.root / "cert.pem"),
                         "-noout", "-text"],
                        check=True, capture_output=True, text=True,
                    ).stdout
                    self.assertIn("CA:FALSE", certificate)
                    self.assertIn("TLS Web Server Authentication", certificate)
                    self.assertIn("DNS:postgres-jobs.chio.invalid", certificate)

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

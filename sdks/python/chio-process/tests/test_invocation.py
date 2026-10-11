import json
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from chio_process import WorkerError
from chio_process.invocation import invoke_recorded


class RecordedInvocationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.chio = self.root / "chio"
        self.chio.write_text("test verifier placeholder")
        self.connection = {
            "socket_path": "/private/operator.sock",
            "credential": "test-secret",
            "runtime_id": "runtime-one",
            "process_id": "operator",
            "capability_id": "operator-cap",
        }
        self.request = {
            "operation_key": "one",
            "server_id": "resource-admin",
            "tool_name": "assign",
            "arguments": {"owner": "old"},
        }

    def test_invalid_requests_do_not_dispatch(self):
        for request in [
            {**self.request, "unexpected": True},
            {**self.request, "operation_key": ""},
            {**self.request, "known_outcome_only": 1},
            {**self.request, "arguments": {"number": float("nan")}},
        ]:
            with (
                self.subTest(request=request),
                patch("chio_process.invocation.ProcessClient") as client,
            ):
                with self.assertRaises(ValueError):
                    invoke_recorded(
                        self.chio, self.connection, "public-key", request, self.root / "output"
                    )
                client.assert_not_called()
                self.assertFalse((self.root / "output").exists())

    def test_uncertain_transport_retains_frozen_request_without_retry(self):
        output = self.root / "output"

        def fail(*args, **kwargs):
            recorded = json.loads((output / "request.json").read_text())
            self.assertTrue(recorded["known_outcome_only"])
            self.request["arguments"]["owner"] = "new"
            self.assertEqual(args[3], {"owner": "old"})
            raise WorkerError("transport_error")

        with (
            patch("chio_process.invocation.ProcessClient") as client,
            patch("chio_process.invocation.subprocess.run") as verifier,
        ):
            client.return_value.invoke.side_effect = fail
            with self.assertRaises(WorkerError):
                invoke_recorded(self.chio, self.connection, "public-key", self.request, output)
            self.assertEqual(client.return_value.invoke.call_count, 1)
            verifier.assert_not_called()
        self.assertFalse(json.loads((output / "unresolved.json").read_text())["automatic_retry"])
        self.assertNotIn("test-secret", (output / "request.json").read_text())

    def test_missing_host_context_refuses_before_dispatch(self):
        for field in ("runtime_id", "process_id", "capability_id"):
            connection = {key: value for key, value in self.connection.items() if key != field}
            with (
                self.subTest(field=field),
                patch("chio_process.invocation.ProcessClient") as client,
            ):
                with self.assertRaisesRegex(ValueError, field):
                    invoke_recorded(
                        self.chio, connection, "pinned-key", self.request, self.root / "output"
                    )
                client.assert_not_called()
                self.assertFalse((self.root / "output").exists())

    def test_verification_failure_keeps_original_response_and_receipt(self):
        output = self.root / "output"
        receipt = '{"large":18446744073709551615,"text":"λ"}'
        response = {"verdict": "allow", "receipt_json": receipt, "output": {"value": {}}}
        with (
            patch("chio_process.invocation.ProcessClient") as client,
            patch("chio_process.invocation.subprocess.run") as verifier,
        ):
            client.return_value.invoke.return_value = response
            verifier.return_value = CompletedProcess([], 1)
            with self.assertRaisesRegex(RuntimeError, "did not verify"):
                invoke_recorded(self.chio, self.connection, "pinned-key", self.request, output)
            self.assertEqual(client.return_value.invoke.call_count, 1)
            self.assertIn("--trusted-kernel-pubkey", verifier.call_args.args[0])
            self.assertIn("verify-process-response", verifier.call_args.args[0])
            self.assertIn(str(output / "request.json"), verifier.call_args.args[0])
            self.assertIn(str(output / "verification-context.json"), verifier.call_args.args[0])
        self.assertEqual((output / "receipts.ndjson").read_text(), receipt + "\n")
        self.assertEqual(json.loads((output / "response.json").read_text()), response)
        self.assertFalse(json.loads((output / "verification.json").read_text())["receipt_verified"])
        context = json.loads((output / "verification-context.json").read_text())
        self.assertEqual(
            context,
            {key: self.connection[key] for key in ("runtime_id", "process_id", "capability_id")},
        )
        self.assertNotIn("test-secret", (output / "verification-context.json").read_text())


if __name__ == "__main__":
    unittest.main()

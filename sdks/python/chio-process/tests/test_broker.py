import json
import unittest
from unittest.mock import patch

from chio_process import ProcessClient, WorkerError
from chio_process.broker import BrokerProcessClient, decode_broker_output


class BrokerTests(unittest.TestCase):
    def test_preparation_failure_never_dispatches_and_recovery_keeps_original_bytes(self):
        client = BrokerProcessClient("/unused", "credential")
        prepared = {"schema": "chio.broker-execute.v1", "proof": {"nonce": "original"}}
        original = {"receipt_json": '{ "unchanged" : true }', "output": {}}
        with patch.object(ProcessClient, "prepare_invocation", return_value=prepared) as prepare:
            with patch.object(ProcessClient, "invoke", return_value=original) as invoke:
                for _ in range(2):
                    self.assertIs(client.invoke("key", "server", "tool", {"a": 1}), original)
                prepare.assert_called_with("key", "server", "tool", {"a": 1})
                self.assertEqual(invoke.call_count, 2)
                invoke.assert_called_with("key", "server", "tool", prepared)
                prepare.side_effect = WorkerError("conflict")
                with self.assertRaises(WorkerError):
                    client.invoke("key", "other", "tool", {"a": 2})
                self.assertEqual(invoke.call_count, 2)

    def test_decoder_rejects_ambiguous_or_incomplete_bodies(self):
        def response(body):
            return {
                "status": 200,
                "headers": [],
                "body": list(body),
                "evidence": {"schema": "chio.broker-execution-evidence.v2"},
                "receiptReference": {},
                "receipt": {},
            }

        value = {"output": "native", "returncode": 0}
        self.assertEqual(decode_broker_output(response(json.dumps(value).encode())), value)
        for body in (b'{"x":1,"x":2}', b'{"x":NaN}', b"\xff", b"{"):
            with self.subTest(body=body), self.assertRaises(WorkerError):
                decode_broker_output(response(body))
        for field, value in (("status", 500), ("evidence", {}), ("body", [True])):
            invalid = response(b"{}")
            invalid[field] = value
            with self.subTest(field=field), self.assertRaises(WorkerError):
                decode_broker_output(invalid)

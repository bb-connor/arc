"""Consumer contract for the kernel's verified broker response value."""

import copy
import json
import unittest

import qualify
from chio_process import WorkerError


class QualificationResponseTests(unittest.TestCase):
    def setUp(self):
        self.resource = {"isError": False, "structuredContent": {"jobs": []}}
        # BrokerMcpConnection consumes the transport's MCP wrapper and returns
        # BrokerExecuteResponse as the kernel value, preserving its evidence.
        self.broker = {
            "status": 200,
            "headers": [],
            "body": list(json.dumps(self.resource).encode()),
            "evidence": {"schema": "chio.broker-execution-evidence.v2"},
            "receiptReference": {},
            "receipt": {},
        }
        self.response = {
            "verdict": "allow",
            "output": {"kind": "value", "value": self.broker},
            "receipt_json": '{ "original": true }',
        }

    def test_direct_broker_value_decodes_without_rewriting_signed_response(self):
        original = copy.deepcopy(self.response)
        self.assertEqual(qualify.value(self.response), {"jobs": []})
        self.assertEqual(self.response, original)

    def test_mcp_wrapper_and_incomplete_broker_evidence_are_refused(self):
        invalid_values = [
            {"isError": False, "structuredContent": self.broker},
            {**self.broker, "status": 500},
            {**self.broker, "evidence": {}},
        ]
        for value in invalid_values:
            with self.subTest(value=value):
                response = {
                    **self.response,
                    "output": {"kind": "value", "value": value},
                }
                with self.assertRaises(WorkerError):
                    qualify.value(response)

    def test_kernel_denial_and_resource_error_cannot_be_success(self):
        with self.assertRaisesRegex(AssertionError, "kernel denial"):
            qualify.value({"verdict": "deny", "output": None})
        self.broker["body"] = list(
            json.dumps({**self.resource, "isError": True}).encode()
        )
        with self.assertRaisesRegex(AssertionError, "prepared resource error"):
            qualify.value(self.response)


if __name__ == "__main__":
    unittest.main()

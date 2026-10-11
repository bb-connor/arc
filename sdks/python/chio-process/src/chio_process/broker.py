"""Prepare through the trusted host, then use its original signed invocation.

This client has no credential, issuer key, destination selector or HTTP fallback.
It returns the original response and receipt unchanged.
"""

import json

from chio_process import ProcessClient, WorkerError


class BrokerProcessClient(ProcessClient):
    def invoke(self, operation_key, server_id, tool_name, arguments, **options):
        prepared = self.prepare_invocation(operation_key, server_id, tool_name, arguments)
        if not isinstance(prepared, dict) or prepared.get("schema") != "chio.broker-execute.v1":
            raise WorkerError("invalid_preparation")
        return super().invoke(operation_key, server_id, tool_name, prepared, **options)


def decode_broker_output(value):
    """Read bounded application JSON; this does not verify or rewrite evidence."""
    fields = {"status", "headers", "body", "evidence", "receiptReference", "receipt"}
    if not isinstance(value, dict) or set(value) != fields or value["status"] != 200:
        raise WorkerError("incomplete_broker_response")
    evidence = value["evidence"]
    if (
        not isinstance(evidence, dict)
        or evidence.get("schema") != "chio.broker-execution-evidence.v2"
    ):
        raise WorkerError("invalid_broker_evidence")
    body = value["body"]
    if (
        not isinstance(body, list)
        or len(body) > 2 * 1024 * 1024
        or any(type(byte) is not int or not 0 <= byte <= 255 for byte in body)
    ):
        raise WorkerError("invalid_broker_body")

    def unique(pairs):
        result = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = item
        return result

    def nonfinite(_):
        raise ValueError("nonfinite JSON")

    try:
        return json.loads(bytes(body), object_pairs_hook=unique, parse_constant=nonfinite)
    except (ValueError, UnicodeError, RecursionError) as error:
        raise WorkerError("invalid_broker_body") from error

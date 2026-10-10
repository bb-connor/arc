"""Retain both logical intent and the exact host-prepared broker invocation."""

from chio_process import ProcessClient
from chio_process.invocation import invoke_recorded

import host


def invoke_resource_recorded(chio, connection, public_key, request, output):
    client = ProcessClient(connection["socket_path"], connection["credential"])
    prepared = client.prepare_invocation(
        request["operation_key"], request["server_id"], request["tool_name"],
        request["arguments"],
    )
    wire_request = {**request, "arguments": prepared}
    try:
        return invoke_recorded(chio, connection, public_key, wire_request, output)
    finally:
        if output.is_dir():
            host.write(output / "logical-request.json", request)

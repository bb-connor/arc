#!/usr/bin/env python3

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent


def load_mock_server():
    spec = importlib.util.spec_from_file_location(
        "docker_mock_mcp_server", HERE / "mock_mcp_server.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load mock_mcp_server.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


server = load_mock_server()


def tool_call(request_id, *, params_marker=False, params=None):
    request = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
    }
    if params_marker:
        request["params"] = params
    return request


def invalid_tool_calls():
    return [
        tool_call(1),
        tool_call(2, params_marker=True, params=[]),
        tool_call(3, params_marker=True, params={}),
        tool_call(4, params_marker=True, params={"arguments": {"message": "ok"}}),
        tool_call(
            5,
            params_marker=True,
            params={"name": "wrong_tool", "arguments": {"message": "ok"}},
        ),
        tool_call(
            6,
            params_marker=True,
            params={"name": "echo_text", "arguments": None},
        ),
        tool_call(
            7,
            params_marker=True,
            params={"name": "echo_text", "arguments": []},
        ),
        tool_call(
            8,
            params_marker=True,
            params={"name": "echo_text", "arguments": "message"},
        ),
        tool_call(
            9,
            params_marker=True,
            params={"name": "echo_text", "arguments": {}},
        ),
        tool_call(
            10,
            params_marker=True,
            params={"name": "echo_text", "arguments": {"message": None}},
        ),
        tool_call(
            11,
            params_marker=True,
            params={"name": "echo_text", "arguments": {"message": False}},
        ),
        tool_call(
            12,
            params_marker=True,
            params={"name": "echo_text", "arguments": {"message": 7}},
        ),
        tool_call(
            13,
            params_marker=True,
            params={"name": "echo_text", "arguments": {"message": []}},
        ),
        tool_call(
            14,
            params_marker=True,
            params={"name": "echo_text", "arguments": {"message": ""}},
        ),
        tool_call(
            15,
            params_marker=True,
            params={
                "name": "echo_text",
                "arguments": {"message": "🧪" * 4097},
            },
        ),
        tool_call(
            16,
            params_marker=True,
            params={
                "name": "echo_text",
                "arguments": {"message": "ok", "extra": True},
            },
        ),
        tool_call(
            17,
            params_marker=True,
            params={
                "name": "echo_text",
                "arguments": {"message": "ok"},
                "extra": True,
            },
        ),
    ]


def valid_tool_call(request_id, message):
    return tool_call(
        request_id,
        params_marker=True,
        params={"name": "echo_text", "arguments": {"message": message}},
    )


class MockMcpSchemaTests(unittest.TestCase):
    def test_advertised_schema_exactly_matches_reviewed_tools_fixture(self):
        fixture = json.loads((HERE / "tools.json").read_text(encoding="utf-8"))
        self.assertEqual(server.TOOLS, fixture["tools"])

    def test_echo_accepts_exact_string_boundaries_including_unicode(self):
        for request_id, message in ((20, "x"), (21, "🧪" * 4096)):
            with self.subTest(request_id=request_id):
                response = server.handle_message(valid_tool_call(request_id, message))
                self.assertEqual(response["id"], request_id)
                self.assertIs(response["result"]["isError"], False)
                self.assertEqual(
                    response["result"]["structuredContent"]["echo"], message
                )

    def test_echo_rejects_every_schema_violation_as_invalid_params(self):
        for request in invalid_tool_calls():
            with self.subTest(request_id=request["id"]):
                response = server.handle_message(request)
                self.assertEqual(response["id"], request["id"])
                self.assertEqual(response["error"]["code"], -32602)

    def test_invalid_calls_do_not_terminalize_the_stdio_server(self):
        messages = []
        for request in invalid_tool_calls():
            messages.append(request)
            messages.append(
                tool_call(
                    request["id"] + 100,
                    params_marker=True,
                    params={
                        "name": "echo_text",
                        "arguments": {"message": "still alive"},
                    },
                )
            )
        completed = subprocess.run(
            [sys.executable, str(HERE / "mock_mcp_server.py")],
            input="".join(f"{json.dumps(message)}\n" for message in messages),
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        responses = [json.loads(line) for line in completed.stdout.splitlines()]
        self.assertEqual(len(responses), len(messages))
        for index in range(0, len(responses), 2):
            self.assertEqual(responses[index]["error"]["code"], -32602)
            self.assertIs(responses[index + 1]["result"]["isError"], False)

    def test_request_methods_with_missing_ids_return_invalid_request(self):
        for method in ("initialize", "tools/list", "tools/call"):
            with self.subTest(method=method):
                request = {"jsonrpc": "2.0", "method": method}
                if method == "tools/call":
                    request["params"] = {
                        "name": "echo_text",
                        "arguments": {"message": "ok"},
                    }
                response = server.handle_message(request)
                self.assertIsNone(response["id"])
                self.assertEqual(response["error"]["code"], -32600)


if __name__ == "__main__":
    unittest.main()

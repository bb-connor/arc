"""Repository line framing preserves valid requests after recoverable input errors."""

import io
import json

import pytest

from chio_mini_swe.repository import serve, tool
from chio_mini_swe.repository_wire import MAX_FRAME, MAX_REQUEST_ID


class Workspace:
    config = {"id": "a" * 32, "source_commit": "b" * 40}

    def __init__(self):
        self.commands = []

    def recover(self):
        pass

    def execute(self, command):
        self.commands.append(command)
        return {"output": "completed", "returncode": 0, "exception_info": ""}


def encoded(message, *, ensure_ascii=True):
    return json.dumps(message, ensure_ascii=ensure_ascii).encode() + b"\n"


def execute(command, *, identifier=1, tool_call_id=None):
    arguments = {"command": command}
    if tool_call_id is not None:
        arguments["tool_call_id"] = tool_call_id
    return {
        "id": identifier,
        "method": "tools/call",
        "params": {"name": "execute", "arguments": arguments},
    }


def run_frames(data):
    workspace, outgoing = Workspace(), io.StringIO()
    serve(workspace, io.BytesIO(data), outgoing)
    return workspace, [json.loads(line) for line in outgoing.getvalue().splitlines()]


@pytest.mark.parametrize(
    "command", ["\\" * 65536, '"' * 65536, "\t" * 65536, "\ufffd" * 21845, "🚀" * 16384]
)
def test_accepted_utf8_commands_fit_escaped_frames_and_preserve_the_next_request(command):
    frame = encoded(execute(command, identifier="\0" * MAX_REQUEST_ID, tool_call_id="\t" * 1024))
    assert 80 * 1024 < len(frame) <= MAX_FRAME
    workspace, replies = run_frames(frame + encoded({"id": 2, "method": "tools/list"}))
    assert workspace.commands == [command]
    assert replies[0]["result"]["isError"] is False
    assert replies[1]["id"] == 2 and replies[1]["result"]["tools"] == [tool(workspace.config)]


def test_schema_character_maximum_fits_wire_while_backend_byte_limit_still_refuses():
    command = "🚀" * 65536
    assert (
        len(command) == tool(Workspace.config)["inputSchema"]["properties"]["command"]["maxLength"]
    )
    frame = encoded(execute(command, identifier="\0" * MAX_REQUEST_ID, tool_call_id="\t" * 1024))
    assert len(frame) <= MAX_FRAME
    workspace, replies = run_frames(frame + encoded({"id": 2, "method": "tools/list"}))
    assert workspace.commands == []
    assert replies[0]["result"]["isError"] is True
    assert replies[1]["id"] == 2


@pytest.mark.parametrize("extra", [0, 1, 17])
def test_oversized_frame_draining_does_not_consume_the_following_request(extra):
    invalid = b"x" * (MAX_FRAME + extra) + b"\n"
    workspace, replies = run_frames(invalid + encoded({"id": 2, "method": "tools/list"}))
    assert workspace.commands == []
    assert replies[0]["id"] is None and "error" in replies[0]
    assert replies[1]["id"] == 2 and "tools" in replies[1]["result"]


@pytest.mark.parametrize(
    "invalid",
    [
        b"{\n",
        b"\xff\n",
        b"[]\n",
        b'{"id":1,"id":2}\n',
        b'{"id":1,"value":NaN}\n',
        b'{"id":true,"method":"tools/list"}\n',
    ],
)
def test_malformed_frames_refuse_without_execution_and_preserve_the_following_request(invalid):
    workspace, replies = run_frames(invalid + encoded({"id": 2, "method": "tools/list"}))
    assert workspace.commands == []
    assert "error" in replies[0]
    assert replies[1]["id"] == 2 and "tools" in replies[1]["result"]


def test_raw_utf8_and_escaped_unicode_use_the_same_command_byte_contract():
    command = "🚀" * 16384
    for ensure_ascii in [False, True]:
        workspace, replies = run_frames(encoded(execute(command), ensure_ascii=ensure_ascii))
        assert workspace.commands == [command]
        assert replies[0]["result"]["isError"] is False


def test_incomplete_frame_at_eof_emits_one_bounded_error_without_execution():
    workspace, replies = run_frames(b'{"id":1')
    assert workspace.commands == []
    assert len(replies) == 1 and "error" in replies[0]


def test_overlong_utf8_id_is_refused_without_losing_the_next_request():
    workspace, replies = run_frames(
        encoded(execute("ok", identifier="🚀" * 257)) + encoded({"id": 2, "method": "tools/list"})
    )
    assert workspace.commands == []
    assert replies[0]["id"] is None and "error" in replies[0]
    assert replies[1]["id"] == 2


def test_utf16_json_is_not_accepted_as_a_utf8_wire_frame():
    invalid = json.dumps({"id": 1, "method": "tools/list"}).encode("utf-16-le") + b"\n"
    workspace, replies = run_frames(invalid + encoded({"id": 2, "method": "tools/list"}))
    assert workspace.commands == []
    assert replies[0]["id"] is None and "error" in replies[0]
    assert replies[1]["id"] == 2


def test_unknown_method_refuses_its_own_id_and_preserves_discovery():
    workspace, replies = run_frames(
        encoded({"id": 1, "method": "unknown"}) + encoded({"id": 2, "method": "tools/list"})
    )
    assert workspace.commands == []
    assert replies[0]["id"] == 1 and replies[0]["error"]["code"] == -32601
    assert replies[1]["id"] == 2

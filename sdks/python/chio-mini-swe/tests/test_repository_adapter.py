import io
import json
from contextlib import nullcontext

import pytest

from chio_mini_swe.repository_adapter import serve
from chio_mini_swe.repository_store import configuration_digest


class Workspace:
    config = {"id": "selected"}

    def __init__(self):
        self.effects = []

    def status(self):
        return {"interrupted": False}

    def execute(self, command):
        self.effects.append(command)
        return {
            "output": "original",
            "workspace": {"configuration_sha256": configuration_digest(self.config)},
        }


def framed(body):
    return len(body).to_bytes(4, "big") + body


def test_only_bound_command_executes_and_emits_original_result():
    workspace = Workspace()
    binding = configuration_digest(workspace.config)
    output = io.BytesIO()
    serve(
        lambda: nullcontext(workspace),
        binding,
        io.BytesIO(
            framed(json.dumps({"command": "one", "configuration_sha256": binding}).encode())
        ),
        output,
    )
    assert workspace.effects == ["one"]
    output.seek(0)
    ready = json.loads(output.read(int.from_bytes(output.read(4), "big")))
    result = json.loads(output.read(int.from_bytes(output.read(4), "big")))
    assert ready["configuration_sha256"] == binding
    assert result == {"output": "original", "workspace": {"configuration_sha256": binding}}
    assert output.read() == b""


@pytest.mark.parametrize(
    "body",
    [
        b'{"command":"one","command":"two"}',
        b'{"command":"one","configuration_sha256":"changed"}',
        b'{"command":"one","configuration_sha256":NaN}',
        b"[1]",
    ],
)
def test_invalid_frame_cannot_invoke_workspace(body):
    workspace = Workspace()
    with pytest.raises(ValueError):
        serve(
            lambda: nullcontext(workspace),
            configuration_digest(workspace.config),
            io.BytesIO(framed(body)),
            io.BytesIO(),
        )
    assert workspace.effects == []


@pytest.mark.parametrize("wire", [b"\0", (131073).to_bytes(4, "big"), b"\0\0\0\x10{}"])
def test_truncated_and_oversize_frames_are_refused(wire):
    workspace = Workspace()
    with pytest.raises(ValueError):
        serve(
            lambda: nullcontext(workspace),
            configuration_digest(workspace.config),
            io.BytesIO(wire),
            io.BytesIO(),
        )
    assert workspace.effects == []


def test_startup_never_recovers_an_interrupted_workspace():
    workspace = Workspace()
    workspace.status = lambda: {"interrupted": True}
    output = io.BytesIO()
    with pytest.raises(ValueError, match="operator recovery"):
        serve(
            lambda: nullcontext(workspace),
            configuration_digest(workspace.config),
            io.BytesIO(),
            output,
        )
    assert output.getvalue() == b""
    assert workspace.effects == []

"""Tests for ARC LangChain tool integration."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from arc_langchain.tool import ArcTool, ArcToolkit, _json_type_to_python
from arc_sdk.errors import ArcDeniedError
from arc_sdk.models import ArcReceipt, Decision, ToolCallAction


BASE = "http://127.0.0.1:9090"


def _make_receipt_dict(allowed: bool = True) -> dict:
    decision = (
        {"verdict": "allow"}
        if allowed
        else {"verdict": "deny", "reason": "no permission", "guard": "TestGuard"}
    )
    return {
        "id": "r-1",
        "timestamp": 1700000000,
        "capability_id": "cap-1",
        "tool_server": "srv",
        "tool_name": "read_file",
        "action": {"parameters": {"path": "/tmp"}, "parameter_hash": "abc"},
        "decision": decision,
        "content_hash": "deadbeef",
        "policy_hash": "cafe",
        "kernel_key": "kk",
        "signature": "ss",
    }


# ---------------------------------------------------------------------------
# ArcTool
# ---------------------------------------------------------------------------


class TestArcTool:
    def test_construction(self) -> None:
        tool = ArcTool(
            name="read_file",
            description="Read a file from disk",
            server_id="fs-server",
            capability_id="cap-1",
            sidecar_url=BASE,
        )
        assert tool.name == "read_file"
        assert tool.server_id == "fs-server"

    def test_sync_raises(self) -> None:
        tool = ArcTool(
            name="t", description="d", server_id="s", capability_id="c"
        )
        with pytest.raises(NotImplementedError):
            tool._run(path="/tmp")

    @respx.mock
    async def test_allowed_invocation(self) -> None:
        respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(200, json=_make_receipt_dict(allowed=True))
        )

        tool = ArcTool(
            name="read_file",
            description="Read file",
            server_id="srv",
            capability_id="cap-1",
            sidecar_url=BASE,
        )
        result = await tool._arun(path="/tmp/test.txt")
        data = json.loads(result)
        assert data["status"] == "allowed"
        assert data["receipt_id"] == "r-1"
        assert tool.last_receipt is not None
        assert tool.last_receipt.is_allowed

    @respx.mock
    async def test_denied_invocation(self) -> None:
        respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(200, json=_make_receipt_dict(allowed=False))
        )

        tool = ArcTool(
            name="read_file",
            description="Read file",
            server_id="srv",
            capability_id="cap-1",
            sidecar_url=BASE,
        )
        result = await tool._arun(path="/etc/shadow")
        data = json.loads(result)
        assert data["error"] == "denied"
        assert data["guard"] == "TestGuard"

    @respx.mock
    async def test_denied_error_from_sidecar(self) -> None:
        respx.post(f"{BASE}/v1/evaluate").mock(
            return_value=httpx.Response(
                403,
                json={
                    "message": "expired",
                    "guard": "TimeGuard",
                    "reason": "token expired",
                },
            )
        )

        tool = ArcTool(
            name="t",
            description="d",
            server_id="s",
            capability_id="c",
            sidecar_url=BASE,
        )
        result = await tool._arun(x=1)
        data = json.loads(result)
        assert data["error"] == "denied"
        assert data["guard"] == "TimeGuard"

    def test_args_schema_generation(self) -> None:
        tool = ArcTool(
            name="test_tool",
            description="A test tool",
            server_id="s",
            capability_id="c",
            input_schema_def={
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path"},
                    "count": {"type": "integer", "description": "Number of items"},
                    "verbose": {"type": "boolean", "description": "Verbose output"},
                },
                "required": ["path"],
            },
        )
        schema = tool.get_input_schema()
        assert schema is not None
        assert "path" in schema.model_fields
        assert "count" in schema.model_fields

    def test_empty_schema(self) -> None:
        tool = ArcTool(
            name="t", description="d", server_id="s", capability_id="c"
        )
        assert tool.get_input_schema() is None


# ---------------------------------------------------------------------------
# ArcToolkit
# ---------------------------------------------------------------------------


class TestArcToolkit:
    def test_create_tool(self) -> None:
        toolkit = ArcToolkit(capability_id="cap-1", sidecar_url=BASE)
        tool = toolkit.create_tool(
            name="write_file",
            description="Write a file",
            server_id="fs-server",
            input_schema={
                "type": "object",
                "properties": {
                    "path": {"type": "string"},
                    "content": {"type": "string"},
                },
                "required": ["path", "content"],
            },
        )
        assert isinstance(tool, ArcTool)
        assert tool.name == "write_file"
        assert tool.capability_id == "cap-1"

    @respx.mock
    async def test_get_tools_from_sidecar(self) -> None:
        health_data = {
            "status": "ok",
            "servers": [
                {
                    "server_id": "fs",
                    "tools": [
                        {
                            "name": "read_file",
                            "description": "Read a file",
                            "input_schema": {
                                "type": "object",
                                "properties": {
                                    "path": {"type": "string"},
                                },
                            },
                        },
                        {
                            "name": "write_file",
                            "description": "Write a file",
                            "input_schema": {},
                        },
                    ],
                },
                {
                    "server_id": "net",
                    "tools": [
                        {
                            "name": "fetch_url",
                            "description": "Fetch a URL",
                            "input_schema": {},
                        },
                    ],
                },
            ],
        }
        respx.get(f"{BASE}/arc/health").mock(
            return_value=httpx.Response(200, json=health_data)
        )

        toolkit = ArcToolkit(capability_id="cap-1", sidecar_url=BASE)
        tools = await toolkit.get_tools()
        assert len(tools) == 3
        assert tools[0].name == "read_file"
        assert tools[0].server_id == "fs"

    @respx.mock
    async def test_get_tools_filtered_by_server(self) -> None:
        health_data = {
            "status": "ok",
            "servers": [
                {
                    "server_id": "fs",
                    "tools": [{"name": "read", "description": "r"}],
                },
                {
                    "server_id": "net",
                    "tools": [{"name": "fetch", "description": "f"}],
                },
            ],
        }
        respx.get(f"{BASE}/arc/health").mock(
            return_value=httpx.Response(200, json=health_data)
        )

        toolkit = ArcToolkit(capability_id="cap-1", sidecar_url=BASE)
        tools = await toolkit.get_tools(server_id="net")
        assert len(tools) == 1
        assert tools[0].name == "fetch"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class TestJsonTypeMapping:
    def test_known_types(self) -> None:
        assert _json_type_to_python("string") is str
        assert _json_type_to_python("integer") is int
        assert _json_type_to_python("number") is float
        assert _json_type_to_python("boolean") is bool
        assert _json_type_to_python("array") is list
        assert _json_type_to_python("object") is dict

    def test_unknown_defaults_to_str(self) -> None:
        assert _json_type_to_python("unknown") is str

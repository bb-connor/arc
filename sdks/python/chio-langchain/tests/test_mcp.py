"""Framework behavior; cryptographic verification is tested in chio-sdk."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from chio.mcp import McpReceiptError, VerifiedMcpResult, VerifiedMcpSession
from chio_langchain.mcp import ChioMcpToolError, ChioMcpToolkit

KEY = "43" * 32
SCHEMA = {
    "type": "object",
    "properties": {
        "item": {
            "type": "object",
            "properties": {"priority": {"enum": ["low", "high"]}},
            "required": ["priority"],
            "additionalProperties": False,
        }
    },
    "required": ["item"],
}


def page(name="save", cursor=None):
    return SimpleNamespace(
        tools=[SimpleNamespace(name=name, description="Save", inputSchema=SCHEMA)],
        nextCursor=cursor,
    )


async def make_tool(monkeypatch, invoke):
    session = SimpleNamespace(list_tools=AsyncMock(return_value=page()))
    monkeypatch.setattr(VerifiedMcpSession, "call_tool", invoke)
    tools = await ChioMcpToolkit(
        session, server_id="journal", trusted_signers=[KEY]
    ).get_tools()
    return tools[0]


async def test_verified_output_and_artifact_reach_tool_message(monkeypatch):
    receipt = {"id": "allow-1", "decision": {"verdict": "allow"}}
    output = {"saved": {"priority": "high"}}
    invoke = AsyncMock(return_value=VerifiedMcpResult(receipt=receipt, output=output))
    tool = await make_tool(monkeypatch, invoke)
    assert tool.args_schema == SCHEMA
    result = await tool.ainvoke(
        {
            "type": "tool_call",
            "id": "model-1",
            "name": "save",
            "args": {"item": {"priority": "high"}},
        }
    )
    assert result.tool_call_id == "model-1"
    assert result.status == "success"
    assert json.loads(result.content) == output
    assert result.artifact == {"receipt": receipt, "output": output}
    invoke.assert_awaited_once_with("save", {"item": {"priority": "high"}})


@pytest.mark.parametrize(
    "verdict,output", [("deny", None), ("allow", {"isError": True, "content": []})]
)
async def test_verified_errors_carry_their_own_receipt(monkeypatch, verdict, output):
    receipt = {
        "id": "error-1",
        "decision": {"verdict": verdict, "reason": "budget exhausted"},
    }
    tool = await make_tool(
        monkeypatch,
        AsyncMock(return_value=VerifiedMcpResult(receipt=receipt, output=output)),
    )
    with pytest.raises(ChioMcpToolError) as caught:
        await tool.ainvoke({"item": {"priority": "high"}})
    assert caught.value.receipt == receipt
    assert caught.value.output == output


async def test_concurrent_errors_keep_independent_evidence(monkeypatch):
    async def invoke(self, name, arguments):
        await asyncio.sleep(0)
        receipt = {"id": arguments["item"]["priority"], "decision": {"verdict": "deny"}}
        return VerifiedMcpResult(receipt=receipt, output=None)

    tool = await make_tool(monkeypatch, invoke)
    results = await asyncio.gather(
        tool.ainvoke({"item": {"priority": "low"}}),
        tool.ainvoke({"item": {"priority": "high"}}),
        return_exceptions=True,
    )
    assert [error.receipt["id"] for error in results] == ["low", "high"]


@pytest.mark.parametrize(
    "failure", [McpReceiptError("tampered"), TimeoutError("unknown effect")]
)
async def test_integrity_and_transport_failures_stop_without_retry(
    monkeypatch, failure
):
    invoke = AsyncMock(side_effect=failure)
    tool = await make_tool(monkeypatch, invoke)
    tool.handle_tool_error = True
    with pytest.raises(type(failure)):
        await tool.ainvoke({"item": {"priority": "high"}})
    assert invoke.await_count == 1


async def test_discovery_preserves_schema_across_pages():
    session = SimpleNamespace(
        list_tools=AsyncMock(side_effect=[page("first", "next"), page("second")])
    )
    tools = await ChioMcpToolkit(
        session, server_id="journal", trusted_signers=[KEY]
    ).get_tools()
    assert [tool.name for tool in tools] == ["first", "second"]
    assert all(tool.args_schema == SCHEMA for tool in tools)
    assert session.list_tools.await_args.kwargs == {"cursor": "next"}


@pytest.mark.parametrize(
    "pages",
    [
        [page("first", "next"), page("first")],
        [page("first", "next"), page("second", "next")],
    ],
)
async def test_discovery_rejects_duplicate_tools_or_cursor(pages):
    session = SimpleNamespace(list_tools=AsyncMock(side_effect=pages))
    with pytest.raises(ValueError):
        await ChioMcpToolkit(
            session, server_id="journal", trusted_signers=[KEY]
        ).get_tools()

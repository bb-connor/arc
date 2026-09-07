"""Adapter contracts; real kernel/restart evidence lives in langgraph_report."""

import asyncio
import copy
import json
import threading
import time

import pytest
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.utils.function_calling import convert_to_openai_tool
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, MessagesState, StateGraph

from chio_langgraph import (
    ChioLangGraphConfigError,
    ChioProcessToolError,
    ChioProcessToolNode,
    ProcessTool,
    process_operation_key,
)

RECEIPT = '{"signed_integer":18446744073709551615}'
TOOL = ProcessTool(
    "publish",
    "reports",
    "append",
    "Publish a report.",
    {
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
    },
)


class Invoker:
    def __init__(self, response=None):
        self.calls = []
        self.response = response

    def invoke(self, key, server, tool, args):
        self.calls.append((key, server, tool, args))
        if isinstance(self.response, Exception):
            raise self.response
        return (
            self.response
            if self.response is not None
            else {
                "request_id": "process:fixture",
                "verdict": "allow",
                "terminal_state": {"state": "completed"},
                "receipt_json": RECEIPT,
                "output": {"kind": "value", "value": args},
            }
        )


def state(message_id="plan-1", call_id="call-1", text="hello"):
    return {
        "messages": [
            AIMessage(
                content="",
                id=message_id,
                tool_calls=[
                    {"name": "publish", "args": {"text": text}, "id": call_id},
                ],
            )
        ]
    }


def node(client=None):
    return ChioProcessToolNode(client or Invoker(), [TOOL], namespace="report-job")


def test_graph_preserves_tool_messages_and_receipts_without_model_content_leak():
    client = Invoker()
    tool_node = node(client)
    graph = StateGraph(MessagesState)
    graph.add_node("tools", tool_node)
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    app = graph.compile(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "thread-1"}}
    result = app.invoke(state(), config)
    message = result["messages"][-1]
    assert isinstance(message, ToolMessage)
    assert message.tool_call_id == "call-1"
    assert json.loads(message.content) == {"text": "hello"}
    assert "signed_integer" not in message.content
    assert message.artifact["chio"]["receipt_json"] == RECEIPT
    assert message.id == client.calls[0][0]
    assert client.calls[0][1:] == ("reports", "append", {"text": "hello"})
    assert app.get_state(config).values["messages"][-1].artifact == message.artifact
    assert convert_to_openai_tool(tool_node.model_schemas()[0])["function"]["name"] == "publish"


def test_persisted_identity_is_stable_but_payload_changes_do_not_mint_new_keys():
    client = Invoker()
    config = {"configurable": {"thread_id": "thread-1"}}
    node(client).invoke(state(), config)
    # A new adapter object simulates worker reconstruction. Credential identity
    # is not part of a logical operation key; the server checks payload binding.
    node(client).invoke(state(text="changed"), config)
    assert client.calls[0][0] == client.calls[1][0]
    for changed in [
        ("other", "thread-1", "plan-1", "call-1"),
        ("report-job", "other", "plan-1", "call-1"),
        ("report-job", "thread-1", "other", "call-1"),
        ("report-job", "thread-1", "plan-1", "other"),
    ]:
        assert process_operation_key(*changed) != client.calls[0][0]
    assert process_operation_key("a:b", "c", "d", "e") != process_operation_key(
        "a", "b:c", "d", "e"
    )


@pytest.mark.parametrize(
    "invalid",
    [
        "missing_thread",
        "missing_message",
        "missing_call",
        "duplicate_call",
        "unknown_tool",
        "invalid_args",
    ],
)
def test_invalid_whole_batch_rejects_before_any_dispatch(invalid):
    client = Invoker()
    request = state()
    config = {"configurable": {"thread_id": "thread-1"}}
    if invalid == "missing_thread":
        config = {}
    elif invalid == "missing_message":
        request["messages"][-1].id = None
    elif invalid == "missing_call":
        request["messages"][-1].tool_calls[0]["id"] = ""
    else:
        second = copy.deepcopy(request["messages"][-1].tool_calls[0])
        if invalid != "duplicate_call":
            second["id"] = "call-2"
        if invalid == "unknown_tool":
            second["name"] = "mint_admin_capability"
        if invalid == "invalid_args":
            second["args"] = []
        request["messages"][-1].tool_calls.append(second)
    with pytest.raises(ChioLangGraphConfigError):
        node(client).invoke(request, config)
    assert not client.calls


@pytest.mark.parametrize(
    "kind", ["deny", "pending", "incomplete", "missing_receipt", "missing_output", "transport"]
)
def test_noncompletion_stops_graph_without_becoming_a_new_model_tool_request(kind):
    response = Invoker().invoke("key", "reports", "append", {})
    if kind in {"deny", "pending"}:
        response["verdict"] = "deny" if kind == "deny" else "pending_approval"
    elif kind == "incomplete":
        response["terminal_state"] = {"state": "incomplete", "reason": "unknown"}
    elif kind == "missing_receipt":
        response.pop("receipt_json")
    elif kind == "missing_output":
        response["output"] = None
    else:
        response = ConnectionError("disconnected")
    client = Invoker(response)
    graph = StateGraph(MessagesState)
    graph.add_node("tools", node(client))
    graph.add_node("model", lambda _: pytest.fail("model must not replan an uncertain effect"))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", "model")
    graph.add_edge("model", END)
    app = graph.compile(checkpointer=InMemorySaver())
    with pytest.raises((ChioProcessToolError, ConnectionError)):
        app.invoke(state(), {"configurable": {"thread_id": "thread-1"}})
    assert len(client.calls) == 1


async def test_async_graph_dispatch_is_off_the_event_loop_and_parallel():
    barrier = threading.Barrier(2, timeout=3)

    class ConcurrentInvoker(Invoker):
        def invoke(self, key, server, tool, args):
            barrier.wait()
            return super().invoke(key, server, tool, args)

    client = ConcurrentInvoker()
    request = state()
    request["messages"][-1].tool_calls.append(
        {"name": "publish", "args": {"text": "two"}, "id": "call-2"}
    )
    ticks = 0
    completed = False

    async def ticker():
        nonlocal ticks
        while not completed:
            ticks += 1
            await asyncio.sleep(0)

    tick = asyncio.create_task(ticker())
    try:
        result = await node(client).ainvoke(request, {"configurable": {"thread_id": "thread-1"}})
    finally:
        completed = True
        await tick
    assert ticks > 0
    assert [m.tool_call_id for m in result["messages"]] == ["call-1", "call-2"]
    assert len(client.calls) == 2


def test_graph_persists_an_assigned_message_id_before_tool_execution():
    class LostReply(Invoker):
        def invoke(self, key, server, tool, args):
            response = super().invoke(key, server, tool, args)
            if len(self.calls) == 1:
                raise ConnectionError("lost reply")
            return response

    client = LostReply()
    graph = StateGraph(MessagesState)
    graph.add_node("tools", node(client))
    graph.add_edge(START, "tools")
    graph.add_edge("tools", END)
    app = graph.compile(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": "thread-1"}}
    with pytest.raises(ConnectionError):
        app.invoke(state(message_id=None), config, durability="sync")
    assigned = app.get_state(config).values["messages"][0].id
    assert assigned
    recovered = app.invoke(None, config, durability="sync")
    assert recovered["messages"][0].id == assigned
    assert client.calls[0][0] == client.calls[1][0]


def test_runtime_concurrency_can_narrow_but_cannot_expand_the_host_ceiling():
    class BoundedInvoker(Invoker):
        def __init__(self):
            super().__init__()
            self.lock = threading.Lock()
            self.active = self.peak = 0

        def invoke(self, key, server, tool, args):
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
            time.sleep(0.01)
            result = super().invoke(key, server, tool, args)
            with self.lock:
                self.active -= 1
            return result

    request = state()
    request["messages"][-1].tool_calls.extend(
        [{"name": "publish", "args": {"text": "extra"}, "id": f"call-{i}"} for i in range(2, 6)]
    )
    for configured, expected in [(1, 1), (8, 2)]:
        client = BoundedInvoker()
        tool_node = ChioProcessToolNode(client, [TOOL], namespace="job", max_concurrency=2)
        tool_node.invoke(
            request, {"configurable": {"thread_id": "t"}, "max_concurrency": configured}
        )
        assert client.peak == expected

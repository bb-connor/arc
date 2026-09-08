"""One LangGraph model loop with Chio and application-owned MCP backends."""

import hashlib
import json

from contract import DEFINITIONS, NAMESPACE
from contract import SCHEMAS as SCHEMAS
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, START, MessagesState, StateGraph
from store import encoded


def wire_messages(messages):
    result = []
    for message in messages:
        if isinstance(message, AIMessage):
            value = {"role": "assistant", "content": message.content or None}
            if message.tool_calls:
                value["tool_calls"] = [
                    {
                        "id": c["id"],
                        "type": "function",
                        "function": {
                            "name": c["name"],
                            "arguments": encoded(c["args"]),
                        },
                    }
                    for c in message.tool_calls
                ]
        elif isinstance(message, ToolMessage):
            value = {
                "role": "tool",
                "tool_call_id": message.tool_call_id,
                "content": message.content,
            }
        else:
            value = {
                "role": {"human": "user", "system": "system"}[message.type],
                "content": message.content,
            }
        result.append(value)
    return result


def assistant(response, definitions=DEFINITIONS):
    identity = response.get("id")
    choices = response.get("choices", [])
    if not isinstance(identity, str) or not identity or len(choices) != 1:
        raise ValueError("provider must return one identified assistant response")
    choice = choices[0]
    if choice.get("finish_reason") not in ("stop", "tool_calls"):
        raise ValueError("provider response did not finish successfully")
    message, calls = choice["message"], []
    seen, names = set(), {t["name"] for t in definitions}
    for call in message.get("tool_calls", []):
        key, function = call.get("id"), call["function"]
        if (
            not isinstance(key, str)
            or not key
            or key in seen
            or function["name"] not in names
        ):
            raise ValueError("invalid, duplicate, or unconfigured provider tool call")
        arguments = json.loads(function["arguments"])
        if not isinstance(arguments, dict):
            raise ValueError("tool arguments must be an object")
        seen.add(key)
        calls.append({"name": function["name"], "id": key, "args": arguments})
    if len(calls) > 16 or (not calls and not message.get("content")):
        raise ValueError("empty or oversized provider response")
    return AIMessage(
        content=message.get("content") or "",
        id=identity,
        tool_calls=calls,
        response_metadata={
            "provider_id": identity,
            "usage": response.get("usage"),
            "model": response.get("model"),
        },
    )


class BaselineTools:
    """Application MCP bridge; requires the same persistent graph prerequisite."""

    def __init__(self, client):
        self.client = client

    def invoke(self, state, config):
        message = state["messages"][-1]
        routes = {t["name"]: t["tool_name"] for t in DEFINITIONS}
        thread = config["configurable"]["thread_id"]
        if not isinstance(message, AIMessage) or not message.id or not thread:
            raise ValueError("persisted graph identities required")
        prepared, seen = [], set()
        for call in message.tool_calls:
            if not call["id"] or call["id"] in seen or call["name"] not in routes:
                raise ValueError("invalid persisted tool call")
            seen.add(call["id"])
            identity = encoded([NAMESPACE, thread, message.id, call["id"]])
            key = "baseline:" + hashlib.sha256(identity.encode()).hexdigest()
            prepared.append((call, key))
        results = []
        for call, key in prepared:
            value = self.client.invoke(key, routes[call["name"]], call["args"])
            results.append(
                ToolMessage(
                    content=encoded(value),
                    id=key,
                    name=call["name"],
                    tool_call_id=call["id"],
                    artifact={"operation_key": key},
                )
            )
        return {"messages": results}


def chio_tools(connection, definitions=DEFINITIONS, namespace=NAMESPACE):
    from chio_langgraph import ChioProcessToolNode, ProcessTool
    from chio_process import ProcessClient

    # The operator descriptor must contain exactly the definitions we advertise.
    supplied = {t["name"]: t for t in connection["tools"]}
    if any(supplied.get(t["name"]) != t for t in definitions):
        raise ValueError("host resource definitions differ from workload definitions")
    return ChioProcessToolNode(
        ProcessClient(connection["socket_path"], connection["credential"]),
        [ProcessTool(**t) for t in definitions],
        namespace=namespace,
        max_concurrency=1,
    )


def build(
    model, tools, saver, *, max_rounds=8, after_tools=None, definitions=DEFINITIONS
):
    schemas = [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["input_schema"],
            },
        }
        for tool in definitions
    ]

    def plan(state):
        turn = sum(isinstance(m, AIMessage) for m in state["messages"])
        if turn >= max_rounds:
            raise RuntimeError("model round limit reached")
        response = model.invoke(turn, wire_messages(state["messages"]), schemas)
        message = assistant(response, definitions)
        if any(previous.id == message.id for previous in state["messages"]):
            raise ValueError("provider repeated an assistant response identity")
        return {"messages": [message]}

    def execute(state, config: RunnableConfig):
        result = tools.invoke(state, config)
        for message in result["messages"]:
            value = json.loads(message.content)
            if value.get("isError") is not False:
                raise RuntimeError("resource returned a tool error")
        if after_tools:
            after_tools(state, result)
        return result

    graph = StateGraph(MessagesState)
    graph.add_node("model", plan)
    graph.add_node("tools", execute)
    graph.add_edge(START, "model")
    graph.add_conditional_edges(
        "model", lambda state: "tools" if state["messages"][-1].tool_calls else END
    )
    graph.add_edge("tools", "model")
    return graph.compile(checkpointer=saver)

"""Execute LangGraph tool calls through an authenticated Chio process.

Graph planning and checkpoint storage remain with LangGraph. Logical tool
identity comes from its persisted thread, assistant message and tool-call ids.
No local tool callback runs after an advisory permission check.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Protocol

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.runnables import Runnable, RunnableConfig

from chio_langgraph.errors import ChioLangGraphConfigError, ChioLangGraphError


class ProcessInvoker(Protocol):
    """The subset of ``chio_process.ProcessClient`` used by this adapter."""

    def invoke(
        self, operation_key: str, server_id: str, tool_name: str, arguments: Any
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ProcessTool:
    """Host-selected model tool definition and kernel routing.

    The input schema describes the tool to the model. Kernel grants, guards
    and the host tool implementation still determine execution authority.
    """

    name: str
    server_id: str
    tool_name: str
    description: str
    input_schema: dict[str, Any]

    def model_schema(self) -> dict[str, Any]:
        """Definition accepted by a LangChain chat model's ``bind_tools``."""
        return {
            "name": self.name,
            "description": self.description,
            "parameters": json.loads(json.dumps(self.input_schema, allow_nan=False)),
        }


class ChioProcessToolError(ChioLangGraphError):
    """The graph must stop on a denial, incomplete result or malformed reply.

    The original receipt is retained when available. Transport failures from
    ProcessClient propagate unchanged and likewise stop the graph. An error
    must never be converted into a fresh tool call to retry an uncertain effect.
    """

    def __init__(self, reason: str, *, receipt_json: str | None = None):
        super().__init__("Chio process tool did not complete", reason=reason)
        self.receipt_json = receipt_json


def _identity(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > 1024
        or any(ord(c) < 32 for c in value)
    ):
        raise ChioLangGraphConfigError(f"{label} must be a nonempty, stable string")
    return value


def process_operation_key(
    namespace: str, thread_id: str, message_id: str, tool_call_id: str
) -> str:
    """Stable identity for one persisted tool call, excluding mutable arguments.

    A changed payload under this identity must conflict in the kernel journal,
    rather than generate another effect. Credentials and attempt counters are
    deliberately absent. Keep namespace stable across worker restarts.
    """
    parts = ["chio.langgraph.tool.v1"]
    for label, value in [
        ("namespace", namespace),
        ("thread_id", thread_id),
        ("message_id", message_id),
        ("tool_call_id", tool_call_id),
    ]:
        parts.append(_identity(value, label))
    encoded = json.dumps(parts, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return "langgraph:" + hashlib.sha256(encoded).hexdigest()


class ChioProcessToolNode(Runnable[dict[str, Any], dict[str, Any]]):
    """A tool node for LangGraph ``MessagesState`` and compatible dictionaries.

    Replace ``ToolNode(local_tools)`` with this node and keep the graph's model
    and control flow. Supply a host-bound ProcessClient; never put its bearer
    credential into graph state or RunnableConfig. Use a persistent LangGraph
    checkpointer and resume with the original thread id after worker restart.

    Supports value and fully materialized stream tool output. Local callbacks,
    injected state/store arguments and tool-produced LangGraph Commands are
    outside this execution profile.
    """

    def __init__(
        self,
        client: ProcessInvoker,
        tools: Sequence[ProcessTool],
        *,
        namespace: str,
        messages_key: str = "messages",
        max_concurrency: int = 4,
    ):
        self._client = client
        self._namespace = _identity(namespace, "namespace")
        self._messages_key = _identity(messages_key, "messages_key")
        if (
            isinstance(max_concurrency, bool)
            or not isinstance(max_concurrency, int)
            or not 1 <= max_concurrency <= 32
        ):
            raise ChioLangGraphConfigError("max_concurrency must be between 1 and 32")
        self._max_concurrency = max_concurrency
        self._tools: dict[str, ProcessTool] = {}
        for tool in tools:
            for label in ["name", "server_id", "tool_name"]:
                _identity(getattr(tool, label), label)
            if tool.name in self._tools:
                raise ChioLangGraphConfigError("duplicate model tool name")
            # Freeze the host's definition against subsequent dict mutation.
            self._tools[tool.name] = ProcessTool(
                tool.name,
                tool.server_id,
                tool.tool_name,
                tool.description,
                json.loads(json.dumps(tool.input_schema, allow_nan=False)),
            )

    def model_schemas(self) -> list[dict[str, Any]]:
        """Pass these definitions to the existing model's ``bind_tools``."""
        return [tool.model_schema() for tool in self._tools.values()]

    def invoke(
        self,
        input: dict[str, Any],
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        configurable = (config or {}).get("configurable", {})
        if not isinstance(configurable, dict):
            raise ChioLangGraphConfigError("configurable must be an object")
        thread_id = _identity(configurable.get("thread_id"), "thread_id")
        requested_concurrency = (config or {}).get("max_concurrency")
        if requested_concurrency is None:
            requested_concurrency = self._max_concurrency
        if (
            isinstance(requested_concurrency, bool)
            or not isinstance(requested_concurrency, int)
            or requested_concurrency < 1
        ):
            raise ChioLangGraphConfigError("runtime max_concurrency must be positive")
        messages = input.get(self._messages_key)
        if (
            not isinstance(messages, list)
            or not messages
            or not isinstance(messages[-1], AIMessage)
        ):
            raise ChioLangGraphConfigError("tool node requires a final persisted AIMessage")
        message = messages[-1]
        message_id = _identity(message.id, "assistant message id")
        if message.invalid_tool_calls:
            raise ChioLangGraphConfigError("assistant message contains invalid tool calls")
        if len(message.tool_calls) > 64:
            raise ChioLangGraphConfigError("tool call batch exceeds 64 calls")
        prepared = []
        seen: set[str] = set()
        for call in message.tool_calls:
            call_id = _identity(call.get("id"), "tool call id")
            if call_id in seen:
                raise ChioLangGraphConfigError("assistant message repeats a tool call id")
            seen.add(call_id)
            tool = self._tools.get(call.get("name", ""))
            if tool is None:
                raise ChioLangGraphConfigError("assistant requested an unconfigured tool")
            if not isinstance(call.get("args"), dict):
                raise ChioLangGraphConfigError("tool arguments must be an object")
            args = json.loads(json.dumps(call["args"], allow_nan=False))
            key = process_operation_key(self._namespace, thread_id, message_id, call_id)
            prepared.append((tool, call_id, key, args))
        if not prepared:
            return {self._messages_key: []}
        # Validate the whole batch before dispatch. On failure, already admitted
        # siblings may finish; replay recovers them under the same identities.
        with ThreadPoolExecutor(
            max_workers=min(self._max_concurrency, requested_concurrency, len(prepared))
        ) as executor:
            results = list(executor.map(self._execute, prepared))
        return {self._messages_key: results}

    async def ainvoke(
        self,
        input: dict[str, Any],
        config: RunnableConfig | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        # Cancelling the caller cannot prove that the kernel did not dispatch.
        # The client thread finishes its exchange; later graph recovery uses
        # the same operation key and never an automatically generated attempt.
        return await asyncio.to_thread(self.invoke, input, config, **kwargs)

    def _execute(self, prepared: tuple[ProcessTool, str, str, dict[str, Any]]) -> ToolMessage:
        tool, call_id, key, args = prepared
        result = self._client.invoke(key, tool.server_id, tool.tool_name, args)
        if not isinstance(result, Mapping):
            raise ChioProcessToolError("invalid_response")
        receipt_json = result.get("receipt_json")
        if not isinstance(receipt_json, str) or not receipt_json:
            raise ChioProcessToolError("missing_receipt")
        if result.get("verdict") != "allow":
            raise ChioProcessToolError("kernel_denied", receipt_json=receipt_json)
        terminal = result.get("terminal_state")
        if not isinstance(terminal, dict) or terminal.get("state") != "completed":
            raise ChioProcessToolError("incomplete", receipt_json=receipt_json)
        output = result.get("output")
        if not isinstance(output, dict):
            raise ChioProcessToolError("missing_output", receipt_json=receipt_json)
        if output.get("kind") == "value" and "value" in output:
            value = output["value"]
        elif output.get("kind") == "stream" and isinstance(output.get("chunks"), list):
            value = {"chunks": output["chunks"]}
        else:
            raise ChioProcessToolError("invalid_output", receipt_json=receipt_json)
        content = (
            value
            if isinstance(value, str)
            else json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
        )
        return ToolMessage(
            content=content,
            name=tool.name,
            tool_call_id=call_id,
            id=key,
            # Receipt artifacts stay out of model-visible tool content. Keep
            # signed JSON text unchanged for an independent Chio verifier.
            artifact={"chio": dict(result), "operation_key": key},
        )

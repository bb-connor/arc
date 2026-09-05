"""Bounded messages and durable exports shared by the adaptive application."""

import json
import os
from pathlib import Path

from langchain_core.messages import AIMessage, ToolMessage

HERE = Path(__file__).resolve().parent.parent
SCHEMA = "chio.repository.adaptive-review.v1"
NAMESPACE = "repository-adaptive-review-v1"


def persist(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as output:
        json.dump(value, output, ensure_ascii=False, allow_nan=False)
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def plan_message(identity, calls):
    return {
        "messages": [
            AIMessage(
                content="",
                id=identity,
                tool_calls=[
                    {"name": name, "id": call_id, "args": arguments}
                    for name, call_id, arguments in calls
                ],
            )
        ]
    }


def value(message):
    result = json.loads(message.content)
    if message.name.startswith("repo__"):
        if result.get("isError") or "structuredContent" not in result:
            raise RuntimeError(
                "repository tool failed; preserve the graph and operation identities"
            )
        return result["structuredContent"]
    if message.name.startswith("chio-ipc__") and result.get("status") not in (
        "sent",
        "received",
        "acknowledged",
    ):
        raise RuntimeError("mailbox did not complete; preserve the graph")
    return result


def tool_messages(state, name=None):
    return [
        message
        for message in state["messages"]
        if isinstance(message, ToolMessage) and (name is None or message.name == name)
    ]


def one_handoff(state, channel):
    messages = tool_messages(state, "chio-ipc__receive_" + channel)
    if len(messages) != 1:
        raise RuntimeError("expected one retained mailbox observation")
    received = value(messages[0])
    if received["status"] != "received" or len(received["messages"]) != 1:
        raise RuntimeError("expected one completed handoff")
    message = received["messages"][0]
    if message["sequence"] != "1" or not isinstance(message["payload"], dict):
        raise RuntimeError("unexpected handoff identity")
    return message["payload"]


def bounded_text(text, limit, label):
    if not isinstance(text, str) or not text.strip() or len(text.encode()) > limit:
        raise ValueError(f"{label} must contain 1-{limit} UTF-8 bytes")
    return text

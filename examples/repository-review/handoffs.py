"""Application handoffs use capability-scoped mailbox tools and graph checkpoints."""

import json

from langchain_core.messages import AIMessage, ToolMessage

PREFIX = "chio-ipc__"


def tool_value(message):
    value = json.loads(message.content)
    if message.name.startswith(PREFIX):
        if value.get("status") not in ("sent", "received", "acknowledged"):
            raise RuntimeError("mailbox did not complete; preserve the existing graph")
        return value
    if value.get("isError") or "structuredContent" not in value:
        raise RuntimeError("MCP tool failed; resume the existing graph after diagnosis")
    return value["structuredContent"]


def handoff_plan(state, role):
    review = state["messages"][-1]
    if (
        not isinstance(review, AIMessage)
        or review.tool_calls
        or not isinstance(review.content, str)
    ):
        raise RuntimeError("handoff requires a completed review")
    if not review.content.strip() or len(review.content.encode()) > 16000:
        raise RuntimeError("review must contain between 1 and 16000 bytes")
    return {
        "messages": [
            AIMessage(
                content="",
                id="handoff-plan",
                tool_calls=[
                    {
                        "name": PREFIX + "send_" + role,
                        "id": "handoff",
                        "args": {
                            "message_key": "review-result",
                            "payload": {"text": review.content},
                        },
                    }
                ],
            )
        ]
    }


def receive_plan(_state):
    return {
        "messages": [
            AIMessage(
                content="",
                id="receive-plan",
                tool_calls=[
                    {
                        "name": PREFIX + "receive_" + role,
                        "id": "receive-" + role,
                        "args": {"after_sequence": "0", "limit": 1},
                    }
                    for role in ("changes", "tests")
                ],
            )
        ]
    }


def received(state):
    messages = {m.name: m for m in state["messages"] if isinstance(m, ToolMessage)}
    result = {}
    for role in ("changes", "tests"):
        value = tool_value(messages[PREFIX + "receive_" + role])
        if value["status"] != "received" or len(value["messages"]) != 1:
            raise RuntimeError("reader handoff is missing; preserve the existing graph")
        message = value["messages"][0]
        if (
            message["sequence"] != "1"
            or not isinstance(message["payload"], dict)
            or not isinstance(message["payload"].get("text"), str)
        ):
            raise RuntimeError("unexpected reader handoff")
        result[role] = message
    return result


def publication_plan(state, config):
    handoffs = received(state)
    report = "\n".join(
        [
            "# Repository change review",
            "",
            f"Base: `{config['base']}`",
            f"Head: `{config['head']}`",
            f"Snapshot: `{config['snapshot_hash']}`",
            "",
            "Mode: "
            + (
                "deterministic inventory; no model review"
                if config["model_factory"] == "inventory"
                else "model review; findings require human verification"
            ),
            "",
            "## Changed code and interfaces",
            "",
            handoffs["changes"]["payload"]["text"],
            "",
            "## Test changes",
            "",
            handoffs["tests"]["payload"]["text"],
            "",
        ]
    )
    return {
        "messages": [
            AIMessage(
                content="",
                id="publication-plan",
                tool_calls=[
                    {
                        "name": "repo__publish_report",
                        "id": "publication",
                        "args": {
                            "report": report,
                            "snapshot_hash": config["snapshot_hash"],
                        },
                    }
                ],
            )
        ]
    }


def acknowledge_plan(state):
    return {
        "messages": [
            AIMessage(
                content="",
                id="acknowledge-plan",
                tool_calls=[
                    {
                        "name": PREFIX + "ack_" + role,
                        "id": "acknowledge-" + role,
                        "args": {"through_sequence": message["sequence"]},
                    }
                    for role, message in received(state).items()
                ],
            )
        ]
    }

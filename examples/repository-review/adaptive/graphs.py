"""Persistent model planning, kernel delegation and cooperative LangGraph joins."""

import importlib

from langchain_core.messages import AIMessage, ToolMessage
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.types import interrupt

from .common import bounded_text, plan_message, tool_messages, value
from .planning import inventory_plan, inventory_text, parse_plan, validate_plan


class ReviewState(MessagesState):
    reviews: list[dict]
    children: list[str]
    rounds: int
    join_round: int
    text: str


def model_node(settings, schemas):
    module, name = settings["model_factory"].split(":", 1)
    model = getattr(importlib.import_module(module), name)(settings["role"])
    bound = model.bind_tools(schemas)

    def invoke(state):
        rounds = state.get("rounds", 0)
        if rounds >= settings["max_rounds"]:
            raise RuntimeError(
                "model round ceiling exhausted; preserve the existing plan"
            )
        message = bound.invoke(state["messages"])
        if not isinstance(message, AIMessage) or message.invalid_tool_calls:
            raise ValueError("model returned an invalid assistant message")
        # The graph checkpoints this identity before any resulting tool effects.
        message.id = f"model-{rounds}"
        if not message.tool_calls:
            bounded_text(message.content, 65536, "model response")
            if not any(isinstance(m, ToolMessage) for m in state["messages"]):
                raise ValueError("model finished without consulting a repository tool")
        return {"messages": [message], "rounds": rounds + 1}

    return invoke


def coordinator(settings, saver, tools, model_schemas):
    builder = StateGraph(ReviewState)
    builder.add_node(
        "inventory_plan",
        lambda _: plan_message("inventory-plan", [("repo__changes", "inventory", {})]),
    )
    builder.add_node("inventory", tools("inventory"))
    builder.add_edge(START, "inventory_plan")
    builder.add_edge("inventory_plan", "inventory")

    def review_plan(state):
        inventory = value(tool_messages(state, "repo__changes")[0])
        paths = [file["path"] for file in inventory["files"]]
        plan = (
            inventory_plan(paths, settings["max_reviews"])
            if settings["model_factory"] == "inventory"
            else parse_plan(state["messages"][-1].content)
        )
        reviews = validate_plan(plan, paths, settings["max_reviews"])
        return {
            "reviews": reviews,
            **plan_message(
                "spawn-plan",
                [
                    (
                        f"chio-process__spawn_review_{job['slot']}",
                        f"review-{job['slot']}",
                        {
                            "input": job,
                            "budget_share_bps": 8000 // settings["max_reviews"],
                        },
                    )
                    for job in reviews
                ],
            ),
        }

    builder.add_node("review_plan", review_plan)
    if settings["model_factory"] == "inventory":
        builder.add_edge("inventory", "review_plan")
    else:
        builder.add_node("model", model_node(settings, model_schemas))
        builder.add_node("model_tools", tools("model_tools", model_only=True))
        builder.add_edge("inventory", "model")
        builder.add_conditional_edges(
            "model",
            lambda state: (
                "model_tools" if state["messages"][-1].tool_calls else "review_plan"
            ),
        )
        builder.add_edge("model_tools", "model")

    def children(state):
        spawned = [
            message
            for message in tool_messages(state)
            if message.name.startswith("chio-process__spawn_")
        ]
        if len(spawned) != len(state["reviews"]):
            raise RuntimeError(
                "spawn completion does not match the checkpointed review plan"
            )
        ids = [value(message)["process"] for message in spawned]
        if len(set(ids)) != len(ids):
            raise RuntimeError("spawn returned duplicate child identities")
        return {"children": ids, "join_round": 0}

    def join_plan(state):
        round_id = state["join_round"]
        return plan_message(
            f"join-plan-{round_id}",
            [
                (
                    "chio-process__wait_children",
                    f"join-{round_id}",
                    {"children": state["children"]},
                )
            ],
        )

    def park(state):
        resumed = interrupt(
            {"schema": "chio.repository.child-wait.v1", "children": state["children"]}
        )
        if resumed != "children_ready":
            raise ValueError("unexpected graph resume command")
        # A new poll observes completed children. The pending poll is retained.
        return {"join_round": state["join_round"] + 1}

    def handoff(state):
        return plan_message(
            "plan-handoff",
            [
                (
                    "chio-ipc__send_plan",
                    "plan-handoff",
                    {
                        "message_key": "review-plan",
                        "payload": {
                            "reviews": state["reviews"],
                            "children": state["children"],
                        },
                    },
                )
            ],
        )

    for name, function in [
        ("spawn", tools("spawn")),
        ("children", children),
        ("join_plan", join_plan),
        ("join", tools("join")),
        ("park", park),
        ("handoff_plan", handoff),
        ("handoff", tools("handoff")),
    ]:
        builder.add_node(name, function)
    for before, after in [
        ("review_plan", "spawn"),
        ("spawn", "children"),
        ("children", "join_plan"),
        ("join_plan", "join"),
        ("park", "join_plan"),
        ("handoff_plan", "handoff"),
        ("handoff", END),
    ]:
        builder.add_edge(before, after)
    builder.add_conditional_edges(
        "join",
        lambda state: (
            "handoff_plan" if value(state["messages"][-1])["complete"] else "park"
        ),
    )
    return builder.compile(checkpointer=saver)


def reviewer(settings, task, saver, tools, model_schemas):
    builder = StateGraph(ReviewState)
    limit = 48000 // settings["max_reviews"]
    if settings["model_factory"] == "inventory":
        builder.add_node(
            "inventory_plan",
            lambda _: plan_message(
                "inventory-plan", [("repo__changes", "inventory", {})]
            ),
        )
        builder.add_node("inventory", tools("inventory"))
        builder.add_node(
            "finish",
            lambda state: {
                "text": inventory_text(value(state["messages"][-1]), task, limit)
            },
        )
        builder.add_edge(START, "inventory_plan")
        builder.add_edge("inventory_plan", "inventory")
        builder.add_edge("inventory", "finish")
    else:
        builder.add_node("model", model_node(settings, model_schemas))
        builder.add_node("model_tools", tools("model_tools", model_only=True))
        builder.add_node(
            "finish",
            lambda state: {
                "text": bounded_text(state["messages"][-1].content, limit, "review")
            },
        )
        builder.add_edge(START, "model")
        builder.add_conditional_edges(
            "model",
            lambda state: (
                "model_tools" if state["messages"][-1].tool_calls else "finish"
            ),
        )
        builder.add_edge("model_tools", "model")

    def handoff(state):
        return plan_message(
            "review-handoff",
            [
                (
                    f"chio-ipc__send_review_{settings['slot']}",
                    "review-handoff",
                    {
                        "message_key": "review-result",
                        "payload": {"slot": settings["slot"], "text": state["text"]},
                    },
                )
            ],
        )

    builder.add_node("handoff_plan", handoff)
    builder.add_node("handoff", tools("handoff"))
    builder.add_edge("finish", "handoff_plan")
    builder.add_edge("handoff_plan", "handoff")
    builder.add_edge("handoff", END)
    return builder.compile(checkpointer=saver)

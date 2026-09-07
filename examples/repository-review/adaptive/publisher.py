"""Publication authority consumes guarded handoffs after all children complete."""

import html
import json

from langgraph.graph import END, START, MessagesState, StateGraph

from .common import bounded_text, one_handoff, plan_message


def graph(settings, saver, tools):
    builder = StateGraph(MessagesState)
    builder.add_node(
        "plan_receive",
        lambda _: plan_message(
            "plan-receive",
            [
                (
                    "chio-ipc__receive_plan",
                    "plan-receive",
                    {"after_sequence": "0", "limit": 1},
                )
            ],
        ),
    )
    builder.add_node("plan_read", tools("plan_read"))

    def reviews(state):
        plan = one_handoff(state, "plan")
        jobs = plan.get("reviews")
        if (
            not isinstance(jobs, list)
            or not 1 <= len(jobs) <= settings["max_reviews"]
            or [job.get("slot") for job in jobs] != list(range(1, len(jobs) + 1))
            or len(plan.get("children", [])) != len(jobs)
        ):
            raise ValueError("invalid coordinator handoff")
        return jobs

    def review_receive(state):
        return plan_message(
            "review-receive",
            [
                (
                    f"chio-ipc__receive_review_{job['slot']}",
                    f"receive-{job['slot']}",
                    {"after_sequence": "0", "limit": 1},
                )
                for job in reviews(state)
            ],
        )

    def publication(state):
        lines = [
            "# Delegated repository review",
            "",
            f"Base: `{settings['base']}`",
            f"Head: `{settings['head']}`",
            f"Snapshot: `{settings['snapshot_hash']}`",
            "",
            "Mode: "
            + (
                "deterministic inventory; no model review"
                if settings["model_factory"] == "inventory"
                else "model review; findings require human verification"
            ),
            "",
        ]
        for job in reviews(state):
            payload = one_handoff(state, f"review_{job['slot']}")
            if payload.get("slot") != job["slot"]:
                raise ValueError("review handoff slot mismatch")
            text = bounded_text(
                payload.get("text"), 48000 // settings["max_reviews"], "review handoff"
            )
            lines += [
                f"## Review {job['slot']}",
                "",
                html.escape(job["focus"]),
                "",
                "Assigned paths: "
                + html.escape(json.dumps(job["paths"], ensure_ascii=False)),
                "",
                text,
                "",
            ]
        report = bounded_text("\n".join(lines), 65536, "report")
        return plan_message(
            "publication-plan",
            [
                (
                    "repo__publish_report",
                    "publication",
                    {"report": report, "snapshot_hash": settings["snapshot_hash"]},
                )
            ],
        )

    def acknowledge(state):
        channels = ["plan"] + [f"review_{job['slot']}" for job in reviews(state)]
        return plan_message(
            "acknowledge-plan",
            [
                (
                    "chio-ipc__ack_" + channel,
                    "ack-" + channel,
                    {"through_sequence": "1"},
                )
                for channel in channels
            ],
        )

    for name, function in [
        ("review_receive", review_receive),
        ("review_read", tools("review_read")),
        ("publication_plan", publication),
        ("publication", tools("publication")),
        ("acknowledge_plan", acknowledge),
        ("acknowledge", tools("acknowledge")),
    ]:
        builder.add_node(name, function)
    chain = [
        START,
        "plan_receive",
        "plan_read",
        "review_receive",
        "review_read",
        "publication_plan",
        "publication",
        "acknowledge_plan",
        "acknowledge",
        END,
    ]
    for before, after in zip(chain, chain[1:]):
        builder.add_edge(before, after)
    return builder.compile(checkpointer=saver)

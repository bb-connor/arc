"""Publication authority consumes guarded handoffs after all children complete."""

from langgraph.graph import END, START, MessagesState, StateGraph

from .common import bounded_text, one_handoff, plan_message, report_text


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
        jobs = reviews(state)
        texts = []
        for job in jobs:
            payload = one_handoff(state, f"review_{job['slot']}")
            if payload.get("slot") != job["slot"]:
                raise ValueError("review handoff slot mismatch")
            text = bounded_text(
                payload.get("text"), 48000 // settings["max_reviews"], "review handoff"
            )
            texts.append(text)
        report = bounded_text(report_text(settings, jobs, texts), 65536, "report")
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

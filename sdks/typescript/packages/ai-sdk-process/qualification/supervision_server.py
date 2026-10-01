"""Controlled provider that chooses a fallback only after seeing a child failure."""

import swarm_server


def planned(request):
    results = swarm_server.outputs(request)
    if request["model"] == "fallback":
        if not results:
            return [
                (
                    "chio-ipc__send_results",
                    {
                        "message_key": "fallback",
                        "payload": {"answer": "Recovered with fallback."},
                    },
                )
            ]
        assert results[-1][1]["status"] == "sent"
        return "Fallback sent."
    assert request["model"] == "supervisor"
    spawns = [
        value["process"] for name, value in results if name.startswith("chio-process__spawn_")
    ]
    joins = [value for name, value in results if name == "chio-process__settle_children"]
    if not spawns:
        return [
            (
                "chio-process__spawn_primary",
                {"input": {"role": "primary"}, "budget_share_bps": 3000},
            )
        ]
    if not joins:
        return [("chio-process__settle_children", {"children": [spawns[0]]})]
    assert joins[0]["complete"] and not joins[0]["successful"]
    assert joins[0]["outcomes"] == [
        {"process": spawns[0], "state": "failed", "attempts": 1, "outcome": "exit_1"}
    ]
    if len(spawns) == 1:
        return [
            (
                "chio-process__spawn_fallback",
                {"input": {"role": "fallback"}, "budget_share_bps": 3000},
            )
        ]
    if len(joins) == 1:
        return [("chio-process__settle_children", {"children": [spawns[1]]})]
    assert joins[1]["complete"] and joins[1]["successful"]
    received = [value for name, value in results if name == "chio-ipc__receive_results"]
    if not received:
        return [("chio-ipc__receive_results", {"after_sequence": "0", "limit": 1})]
    assert len(received[0]["messages"]) == 1
    assert received[0]["messages"][0]["payload"] == {"answer": "Recovered with fallback."}
    if not any(name == "chio-ipc__send_final" for name, _ in results):
        return [
            (
                "chio-ipc__send_final",
                {"message_key": "answer", "payload": received[0]["messages"][0]["payload"]},
            )
        ]
    return "Recovered with fallback."


if __name__ == "__main__":
    swarm_server.planned = planned
    swarm_server.main()

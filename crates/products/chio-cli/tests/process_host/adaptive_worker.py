"""Parent and delegated branch used by the real adaptive-runner qualification."""

import json
import os
import sys
import time
from pathlib import Path

from chio_process import ProcessClient, WorkerError


def save(path, value):
    with path.open("w") as output:
        json.dump(value, output)
        output.flush()
        os.fsync(output.fileno())


def refused(client, key, tool, arguments, server="chio-process"):
    try:
        response = client.invoke(key, server, tool, arguments)
    except WorkerError as failure:
        assert failure.code in {"kernel_error", "conflict"}, failure
        return
    assert response["verdict"] == "deny", response


def main():
    bootstrap = json.load(sys.stdin)
    connection = bootstrap["connection"]
    client = ProcessClient(connection["socket_path"], connection["credential"])
    role = connection["process_id"]
    data = bootstrap["input"]
    # Declared workers receive the plan input; adaptive children receive it as
    # the template configuration next to their task.
    config = data["configuration"] if "task" in data else data
    directory = Path(config["directory"])
    attempt = bootstrap["attempt"]
    save(directory / f"{role}-{attempt}-started.json", {"pid": os.getpid()})

    def invoke(key, tool, arguments, server="chio-process"):
        response = client.invoke(key, server, tool, arguments)
        assert response["verdict"] == "allow", response
        save(directory / f"{role}-{key}-{attempt}.json", response)
        return response["output"]["value"]

    if config.get("probe"):
        probe = config["probe"]
        if probe == "cycle":
            refused(client, "cycle", "wait_children", {"children": ["dependent"]})
        elif probe == "quota":
            invoke(
                "first", "spawn_leaf", {"input": {"value": 1}, "budget_share_bps": 6000}
            )
            refused(
                client,
                "over-budget",
                "spawn_leaf",
                {"input": {"value": 2}, "budget_share_bps": 6000},
            )
        elif probe == "limit":
            invoke(
                "first", "spawn_leaf", {"input": {"value": 1}, "budget_share_bps": 2000}
            )
            refused(
                client,
                "over-count",
                "spawn_leaf",
                {"input": {"value": 2}, "budget_share_bps": 2000},
            )
        elif probe == "cancel":
            invoke(
                "first", "spawn_leaf", {"input": {"value": 1}, "budget_share_bps": 2000}
            )
            save(directory / "probe-entered.json", {"probe": probe})
            client.cancel()
            try:
                client.invoke(
                    "after-cancel",
                    "chio-process",
                    "spawn_leaf",
                    {"input": {}, "budget_share_bps": 1},
                )
            except WorkerError:
                pass
            else:
                raise AssertionError("cancelled parent admitted another call")
        elif probe == "suspend_limit":
            child = invoke(
                "first", "spawn_leaf", {"input": {"value": 1}, "budget_share_bps": 2000}
            )["process"]
            assert not invoke("wait", "wait_children", {"children": [child]})[
                "complete"
            ]
            save(directory / "probe-completed.json", {"probe": probe})
            sys.exit(75)
        elif probe == "fair":
            checkpoint = client.inspect()["checkpoint"]
            waiting = (
                checkpoint["value"] if isinstance(checkpoint["value"], dict) else {}
            )
            if waiting.get("phase") != "waiting":
                first = 1 if role == "root" else 4
                children = [
                    invoke(
                        f"leaf-{index}",
                        "spawn_leaf",
                        {"input": {"value": first + index}, "budget_share_bps": 1000},
                    )["process"]
                    for index in range(3)
                ]
                assert not invoke("wait", "wait_children", {"children": children})[
                    "complete"
                ]
                client.checkpoint(
                    checkpoint["revision"], {"phase": "waiting", "children": children}
                )
                sys.exit(75)
            assert invoke(
                "wait-complete", "wait_children", {"children": waiting["children"]}
            )["complete"]
            save(directory / f"{role}-probe-completed.json", {"probe": probe})
            return
        save(directory / "probe-completed.json", {"probe": probe})
        return

    checkpoint = client.inspect()["checkpoint"]
    resumed = (
        checkpoint["value"].get("phase") == "waiting"
        if isinstance(checkpoint["value"], dict)
        else False
    )
    if not resumed:
        children = []
        if role == "root":
            first = {"input": {"values": [2, 3]}, "budget_share_bps": 4000}
            children.append(invoke("branch", "spawn_branch", first)["process"])
            if attempt == 1:
                if config.get("host_crash"):
                    while True:
                        time.sleep(0.05)
                if config.get("recover"):
                    os._exit(77)
            refused(
                client, "branch", "spawn_branch", {**first, "input": {"values": [9]}}
            )
            refused(
                client,
                "forged-parent",
                "spawn_leaf",
                {"input": {}, "budget_share_bps": 1, "parent_id": children[0]},
            )
            refused(
                client,
                "unknown-template",
                "spawn_missing",
                {"input": {}, "budget_share_bps": 1},
            )
            children.append(
                invoke(
                    "leaf",
                    "spawn_leaf",
                    {"input": {"value": 5}, "budget_share_bps": 4000},
                )["process"]
            )
        else:
            refused(
                client,
                "broader-template",
                "spawn_broad",
                {"input": {}, "budget_share_bps": 1},
            )
            refused(
                client,
                "receive-scope",
                "receive_results",
                {"after_sequence": "0", "limit": 1},
                "chio-ipc",
            )
            for index, value in enumerate(data["task"]["values"]):
                children.append(
                    invoke(
                        f"leaf-{index}",
                        "spawn_leaf",
                        {"input": {"value": value}, "budget_share_bps": 2000},
                    )["process"]
                )
        joined = invoke("wait-initial", "wait_children", {"children": children})
        assert not joined["complete"], (
            "single-slot children ran before parent suspension"
        )
        client.checkpoint(
            checkpoint["revision"], {"phase": "waiting", "children": children}
        )
        sys.exit(75)
    children = checkpoint["value"]["children"]
    # The earlier pending observation retains its original receipt and result.
    assert not invoke("wait-initial", "wait_children", {"children": children})[
        "complete"
    ]
    assert invoke("wait-complete", "wait_children", {"children": children})["complete"]
    if role == "root":
        messages = invoke(
            "results",
            "receive_results",
            {"after_sequence": "0", "limit": 16},
            "chio-ipc",
        )["messages"]
        values = sorted(message["payload"]["value"] for message in messages)
        assert values == [2, 3, 5], values
        invoke(
            "ack",
            "ack_results",
            {"through_sequence": messages[-1]["sequence"]},
            "chio-ipc",
        )
        save(directory / "result.json", {"values": values, "total": sum(values)})


if __name__ == "__main__":
    main()

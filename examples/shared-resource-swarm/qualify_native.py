"""Scripted graph recovery through the public host and real resource MCP service."""

import argparse
import json
import os
from pathlib import Path

import graph
import run
import store
from langchain_core.messages import HumanMessage
from langgraph.checkpoint.memory import InMemorySaver
from provider import SavedChat
from test_graph import response

HERE = Path(__file__).resolve().parent


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(mode=0o700)
    for name in run.ROLES:
        (directory / name).mkdir(mode=0o700)
    store.initialize(
        directory / "resource.db", json.loads((HERE / "seed.json").read_text())
    )
    binary, key = run.prepare_host(args, directory)
    connection_path = directory / "compatibility" / "connection.json"
    connection = json.loads(connection_path.read_text())
    plans = [
        response(0, [("board__read", {"document": "release-board"})]),
        response(
            1,
            [
                (
                    "board__replace",
                    {
                        "document": "release-board",
                        "expected_version": 0,
                        "value": {"assessments": {"api": "fixture"}},
                    },
                )
            ],
        ),
        response(2),
    ]
    provider_calls, original_receipts = [], []

    def transport(request):
        provider_calls.append(request)
        return plans[len(provider_calls) - 1]

    def model():
        return SavedChat(
            directory / "model.db",
            "fixture",
            transport=transport,
            evidence_kind="scripted_test",
        )

    def gap(state, result):
        if state["messages"][-1].tool_calls[0]["name"] == "board__replace":
            original_receipts.append(
                result["messages"][0].artifact["chio"]["receipt_json"]
            )
            raise RuntimeError("qualification checkpoint gap")

    saver = InMemorySaver()
    config = {"configurable": {"thread_id": "native-resource-qualification"}}
    with run.host(binary, key, directory) as process:
        app = graph.build(model(), graph.chio_tools(connection), saver, after_tools=gap)
        try:
            app.invoke(
                {
                    "messages": [
                        HumanMessage(content="Exercise resource", id="assignment")
                    ]
                },
                config,
                durability="sync",
            )
        except RuntimeError as error:
            if str(error) != "qualification checkpoint gap":
                raise
        else:
            raise AssertionError("checkpoint gap did not execute")
        assert app.get_state(config).next == ("tools",)
        assert len(original_receipts) == 1 and len(provider_calls) == 2
        process.kill()
        process.wait(timeout=10)

    # Abrupt host death leaves its socket. Use a fresh path and rotate the
    # credential while retaining the same process, capability and journals.
    socket_path = directory / "recovery.sock"
    replacement = directory / "compatibility" / "connection-resume.json"
    run.command(
        [
            binary,
            "process",
            "credential",
            "--state",
            directory / "host",
            "--process",
            "compatibility",
            "--socket",
            socket_path,
            "--out",
            replacement,
        ],
        directory,
    )
    connection = json.loads(replacement.read_text())
    with run.host(binary, key, directory, socket_path):
        resumed = graph.build(model(), graph.chio_tools(connection), saver)
        result = resumed.invoke(None, config, durability="sync")
    assert result["messages"][-1].content == "Finished."
    replacement_message = next(
        m for m in result["messages"] if m.type == "tool" and m.name == "board__replace"
    )
    assert replacement_message.artifact["chio"]["receipt_json"] == original_receipts[0]
    snapshot = store.inspect(directory / "resource.db")
    assert len(snapshot["mutations"]) == 1
    operation_id = snapshot["mutations"][0]["operation_id"]
    operation = next(o for o in snapshot["operations"] if o["id"] == operation_id)
    assert operation["deliveries"] == 1
    assert len(provider_calls) == 3
    (directory / "receipts.ndjson").write_text(original_receipts[0] + "\n")
    run.command(
        [
            binary,
            "receipt",
            "verify",
            "--input",
            directory / "receipts.ndjson",
            "--trusted-kernel-pubkey",
            directory / "kernel.pub",
        ],
        directory,
    )
    run.write(
        directory / "qualification.json",
        {
            "evidence_kind": "scripted_native_host",
            "live_model": False,
            "host_killed": True,
            "resource_mutations": 1,
            "resource_deliveries": 1,
            "original_receipt_recovered_and_verified": True,
            "graph_checkpoint": "in_memory_retained_by_test_driver",
            "provider_calls": len(provider_calls),
            "resource": snapshot,
        },
    )
    print(
        store.encoded(
            {"qualified": True, "output": str(directory / "qualification.json")}
        )
    )


if __name__ == "__main__":
    main()

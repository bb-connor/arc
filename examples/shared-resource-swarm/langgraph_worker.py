"""Execute or resume one externally managed LangGraph worker from private stdin."""

import contextlib
import fcntl
import json
import os
import sqlite3
import sys
import time
from importlib.metadata import version
from pathlib import Path

from contract import INSTRUCTION
from graph import BaselineTools, build, chio_tools
from langchain_core.messages import HumanMessage, SystemMessage, ToolMessage
from mcp_client import McpClient
from provider import SavedChat
from store import encoded

HERE = Path(__file__).resolve().parent


def run(settings, saver, model, tools):
    app = build(model, tools, saver, max_rounds=settings["max_rounds"])
    config = {
        "configurable": {"thread_id": settings["thread_id"]},
        "recursion_limit": 2 * settings["max_rounds"] + 4,
        "max_concurrency": 1,
    }
    state = app.get_state(config)
    if state.values and not state.next:
        result = state.values
    else:
        initial = (
            None
            if state.values
            else {
                "messages": [
                    SystemMessage(
                        content=INSTRUCTION,
                        id="system",
                    ),
                    HumanMessage(
                        content="Assigned services: " + encoded(settings["services"]),
                        id="assignment",
                    ),
                ]
            }
        )
        result = app.invoke(initial, config, durability="sync")
    tool_messages = [m for m in result["messages"] if isinstance(m, ToolMessage)]
    return {
        "text": result["messages"][-1].content,
        "model_calls": model.evidence(),
        "tools": [m.model_dump() for m in tool_messages],
        "graph_finished": not app.get_state(config).next,
    }


def main():
    from langgraph.checkpoint.sqlite import SqliteSaver

    os.umask(0o077)
    bootstrap = json.load(sys.stdin)
    settings = bootstrap["input"]
    directory = Path(settings["directory"]).resolve(strict=True)
    if (
        type(settings["max_rounds"]) is not int
        or not 1 <= settings["max_rounds"] <= 12
        or settings["backend"] not in ("baseline", "chio")
        or settings["provider"] not in ("openai", "openrouter")
        or not settings["services"]
        or not settings["thread_id"]
        or not settings["model"]
    ):
        raise ValueError("invalid worker settings")
    # One process owns this graph/model journal. A second live attempt must fail.
    with (directory / "worker.lock").open("a") as lock, contextlib.ExitStack() as stack:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        binding = directory / "input.json"
        if binding.exists():
            if json.loads(binding.read_text()) != settings:
                raise ValueError("worker input changed across recovery")
            if not all(
                (directory / name).is_file() for name in ("graph.db", "model.db")
            ):
                raise ValueError("worker recovery journal is missing")
        else:
            for name in ("graph.db", "model.db"):
                with (directory / name).open("xb"):
                    pass
            persist(binding, settings)
        if settings["backend"] == "baseline":
            client = stack.enter_context(
                McpClient(
                    [
                        sys.executable,
                        str(HERE / "server.py"),
                        "--database",
                        settings["database"],
                    ]
                )
            )
            tools = BaselineTools(client)
        else:
            tools = chio_tools(bootstrap["connection"])
        db = stack.enter_context(
            contextlib.closing(
                sqlite3.connect(directory / "graph.db", check_same_thread=False)
            )
        )
        db.execute("PRAGMA synchronous=FULL")
        model = SavedChat(
            directory / "model.db",
            settings["model"],
            evidence_kind="live_" + settings["provider"],
        )
        started = time.monotonic()
        result = run(settings, SqliteSaver(db), model, tools)
        result.update(
            backend=settings["backend"],
            elapsed_seconds=time.monotonic() - started,
            versions={
                name: version(name)
                for name in (
                    "langgraph",
                    "langchain-core",
                    "langgraph-checkpoint-sqlite",
                )
            },
        )
        persist(directory / "result.json", result)
        print(
            encoded(
                {
                    "graph_finished": result["graph_finished"],
                    "result": str(directory / "result.json"),
                }
            )
        )


def persist(path, value):
    temporary = path.with_suffix(".tmp")
    with temporary.open("w") as output:
        output.write(encoded(value))
        output.flush()
        os.fsync(output.fileno())
    temporary.replace(path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


if __name__ == "__main__":
    main()

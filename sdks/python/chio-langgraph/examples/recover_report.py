"""One graph, two tool backends, and a worker death before graph checkpoint.

The planning trace is deterministic. No model account or network is used.
Run via Chio's langgraph_report Rust example so the Chio path uses a real kernel.
"""

import json
import os
import sqlite3
import sys
from importlib.metadata import version
from pathlib import Path

from chio_process import ProcessClient
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langchain_core.tools import tool
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

from chio_langgraph import ChioProcessToolNode, ProcessTool


def build_graph(tool_node, phase, checkpointer):
    """Control flow and planning are identical for both execution backends."""

    def plan(_state):
        return {
            "messages": [
                AIMessage(
                    content="",
                    id="read-plan",
                    tool_calls=[
                        {
                            "name": "read_source",
                            "id": "read-runtime",
                            "args": {"source": "runtime"},
                        },
                        {"name": "read_source", "id": "read-worker", "args": {"source": "worker"}},
                    ],
                )
            ]
        }

    def compose(state):
        documents = [
            json.loads(message.content)
            for message in state["messages"]
            if isinstance(message, ToolMessage) and message.name == "read_source"
        ]
        lines = ["# Chio process contract inventory", ""]
        for document in sorted(documents, key=lambda item: item["source"]):
            lines.extend([f"## {document['source']}", ""])
            lines.extend(
                line
                for line in document["content"].splitlines()
                if any(
                    word in line.lower()
                    for word in [
                        "checkpoint",
                        "cancel",
                        "credential",
                        "recovery",
                        "does not",
                        "outside",
                    ]
                )
            )
            lines.append("")
        return {
            "messages": [
                AIMessage(
                    content="",
                    id="publish-plan",
                    tool_calls=[
                        {
                            "name": "publish_report",
                            "id": "publish-report",
                            "args": {"report": "\n".join(lines)},
                        },
                    ],
                )
            ]
        }

    def publish(state, config):
        result = tool_node.invoke(state, config)
        if phase == "first":
            # Test oracle only. Neither graph nor tool backend reads this file
            # during recovery. It lets the Rust host compare original receipts.
            evidence = Path(config["configurable"]["evidence_directory"]) / "first-publication.json"
            with evidence.open("w") as output:
                json.dump(result, output, default=lambda message: message.model_dump())
                output.flush()
                os.fsync(output.fileno())
            # Both backends have returned their successful tool result here.
            # The LangGraph node has not returned, so its checkpoint is absent.
            os._exit(76)
        return result

    graph = StateGraph(MessagesState)
    graph.add_node("plan", plan)
    graph.add_node("read_sources", tool_node)
    graph.add_node("compose", compose)
    graph.add_node("publish", publish)
    graph.add_node(
        "finish", lambda _: {"messages": [AIMessage(content="Report published.", id="finished")]}
    )
    for source, target in [
        (START, "plan"),
        ("plan", "read_sources"),
        ("read_sources", "compose"),
        ("compose", "publish"),
        ("publish", "finish"),
        ("finish", END),
    ]:
        graph.add_edge(source, target)
    return graph.compile(checkpointer=checkpointer)


def baseline_tools(directory):
    @tool
    def read_source(source: str) -> dict:
        """Read one host-selected source document."""
        sources = json.loads((directory / "sources.json").read_text())
        return {"source": source, "content": sources[source]}

    @tool
    def publish_report(report: str) -> dict:
        """Append a report to the local publication log."""
        with (directory / "publications.jsonl").open("a") as output:
            output.write(
                json.dumps({"report": report}, separators=(",", ":"), ensure_ascii=False) + "\n"
            )
            output.flush()
            os.fsync(output.fileno())
        return {"published": True}

    return ToolNode([read_source, publish_report])


def main():
    # Credentials arrive through private stdin, not argv or graph state.
    config = json.load(sys.stdin)
    directory = Path(config["directory"])
    if config["backend"] == "baseline":
        tools = baseline_tools(directory)
    else:
        client = ProcessClient(config["socket_path"], config["credential"])
        tools = ChioProcessToolNode(
            client,
            [
                ProcessTool(
                    "read_source",
                    "tools",
                    "read",
                    "Read a source document.",
                    {
                        "type": "object",
                        "properties": {"source": {"type": "string"}},
                        "required": ["source"],
                    },
                ),
                ProcessTool(
                    "publish_report",
                    "tools",
                    "append",
                    "Publish the report.",
                    {
                        "type": "object",
                        "properties": {"report": {"type": "string"}},
                        "required": ["report"],
                    },
                ),
            ],
            namespace="contract-inventory-v1",
        )
    with sqlite3.connect(directory / "graph.db", check_same_thread=False) as connection:
        saver = SqliteSaver(connection)
        app = build_graph(tools, config["phase"], saver)
        run_config = {
            "configurable": {
                "thread_id": "contract-inventory",
                "evidence_directory": str(directory),
            }
        }
        if config["phase"] == "resume":
            checkpoint = app.get_state(run_config)
            assert checkpoint.next == ("publish",), checkpoint.next
            graph_input = None
        else:
            graph_input = {
                "messages": [HumanMessage(content="Inventory the process contract.", id="request")]
            }
        result = app.invoke(graph_input, run_config, durability="sync")
        tools = [message for message in result["messages"] if isinstance(message, ToolMessage)]
        assert len(tools) == 3
        assert result["messages"][-1].content == "Report published."
        print(
            json.dumps(
                {
                    "backend": config["backend"],
                    "complete": True,
                    "versions": {
                        name: version(name)
                        for name in [
                            "langgraph",
                            "langchain-core",
                            "langgraph-checkpoint",
                            "langgraph-checkpoint-sqlite",
                        ]
                    },
                    "tool_results": [message.model_dump() for message in tools],
                }
            )
        )


if __name__ == "__main__":
    main()

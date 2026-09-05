"""Scripted qualification model. No provider or live model is called."""

import json
import os

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage


class Model:
    def __init__(self, role, invalid=False):
        self.role = role
        self.invalid = invalid

    def bind_tools(self, schemas):
        assert {schema["name"] for schema in schemas} == {
            "repo__changes",
            "repo__read_file",
        }
        return self

    def invoke(self, messages):
        outputs = [message for message in messages if isinstance(message, ToolMessage)]
        reads = [message for message in outputs if message.name == "repo__read_file"]
        if self.role == "coordinator":
            inventory = json.loads(
                next(
                    message for message in outputs if message.name == "repo__changes"
                ).content
            )["structuredContent"]
            paths = [file["path"] for file in inventory["files"]]
            if not reads:
                result = AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "repo__read_file",
                            "id": "planning-read",
                            "args": {"path": paths[0], "revision": "head"},
                        }
                    ],
                )
                kind = "planning-read"
            else:
                selected = ["outside.py"] if self.invalid else paths
                result = AIMessage(
                    content=json.dumps(
                        {
                            "reviews": [
                                {
                                    "paths": [path],
                                    "focus": "Inspect before and after content and report the observed line change.",
                                }
                                for path in selected
                            ]
                        }
                    )
                )
                kind = "plan"
        else:
            assignment = json.loads(
                next(
                    message.content
                    for message in messages
                    if isinstance(message, HumanMessage)
                )
            )["assignment"]
            path = assignment["paths"][0]
            if not reads:
                result = AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "repo__read_file",
                            "id": "read-" + revision,
                            "args": {"path": path, "revision": revision},
                        }
                        for revision in ("base", "head")
                    ],
                )
                kind = "review-read"
            else:
                contents = [
                    json.loads(message.content)["structuredContent"]
                    for message in reads
                ]
                assert len(contents) == 2
                assert contents[1]["content"].startswith("1: ")
                assert "uncommitted" not in contents[1]["content"]
                result = AIMessage(
                    content=f"Observed {path}, head line 1: {contents[1]['content']}. Scripted qualification observation; no live model or test execution."
                )
                kind = "review-finish"
        trace = os.environ.get("CHIO_ADAPTIVE_MODEL_TRACE")
        if trace:
            with open(trace, "a") as output:
                output.write(json.dumps({"role": self.role, "kind": kind}) + "\n")
        return result


def create(role):
    return Model(role)


def invalid(role):
    return Model(role, invalid=True)

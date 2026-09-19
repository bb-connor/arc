"""Qualification-only scripted model. This is not a live model evaluation."""

import json

from langchain_core.messages import AIMessage, ToolMessage


class ScriptedModel:
    def __init__(self, role):
        self.role = role

    def bind_tools(self, schemas):
        assert "repo__publish_report" not in {s["name"] for s in schemas}
        assert all(s["name"].startswith("repo__") for s in schemas)
        return self

    def invoke(self, messages):
        tool_results = [m for m in messages if isinstance(m, ToolMessage)]
        if not tool_results:
            name = "changes" if self.role == "changes" else "test_inventory"
            return AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "repo__" + name,
                        "id": "inventory",
                        "args": {},
                    }
                ],
            )
        if len(tool_results) == 1:
            if self.role == "tests":
                inventory = json.loads(tool_results[0].content)["structuredContent"]
                assert "app.py" in inventory["other_changed_paths"]
            return AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "repo__read_file",
                        "id": "read-" + revision,
                        "args": {"path": "app.py", "revision": revision},
                    }
                    for revision in ("base", "head")
                ],
            )
        data = [json.loads(m.content)["structuredContent"] for m in tool_results[1:]]
        assert "1: value = 1" in data[0]["content"]
        assert "1: value = 2" in data[1]["content"]
        return AIMessage(
            content="Observed app.py, head line 1: value changes from 1 to 2. "
            "Scripted qualification observation; no LLM was called."
        )


def create(role):
    return ScriptedModel(role)

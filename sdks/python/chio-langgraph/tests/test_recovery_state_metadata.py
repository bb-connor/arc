"""Graph checkpoints preserve bounded native metadata without execution authority."""
import json
from pathlib import Path
from typing import TypedDict

import httpx
import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from chio_langgraph.recovery import recovery_node
from chio_sdk.recovery_host import RecoveryHostSession

ROOT = Path(__file__).resolve().parents[4]
CASES = json.loads((ROOT / "sdks/tests/recovery-response-states.json").read_text())


class State(TypedDict):
    choice: str
    recovery: dict[str, str]


def graph(session):
    builder = StateGraph(State)
    builder.add_node("recover", recovery_node(session))
    builder.add_edge(START, "recover")
    builder.add_edge("recover", END)
    return builder.compile(checkpointer=InMemorySaver())


@pytest.mark.asyncio
@pytest.mark.parametrize("effect", CASES["effects"], ids=lambda value: value["kind"])
async def test_graph_checkpoint_preserves_native_state_dimensions(effect):
    corpus = json.loads((ROOT / "spec/vectors/recovery/v1/authority-contracts.json").read_text())
    response = json.loads(next(row["wire"] for row in corpus["vectors"]
                               if row["contract"] == "command_result" and row["valid"]))
    response["status"].update(effect=effect, control="quarantined",
                              release={"kind": "withheld", "evidence": "evidence"})
    response["original_response"]["result"] = {"secret": "raw-result-canary"}
    calls = []
    def serve(request):
        calls.append(request)
        return httpx.Response(200, json=response)
    session = RecoveryHostSession("http://localhost:1", "synthetic-credential",
        {"inspect": b"{}"}, transport=httpx.MockTransport(serve))
    app = graph(session)
    config = {"configurable": {"thread_id": "public-response-test"}}
    result = await app.ainvoke({"choice": "inspect"}, config)
    expected = {"category": "quarantined", "command_id": response["status"]["command_id"],
                "workflow_id": response["status"]["workflow_id"], "effect": effect["kind"],
                "control": "quarantined", "release": "withheld"}
    assert result["recovery"] == expected
    checkpoint = (await app.aget_state(config)).values
    assert checkpoint["recovery"] == expected
    assert "canary" not in json.dumps(checkpoint) and "synthetic-credential" not in json.dumps(checkpoint)
    assert len(calls) == session.attempts == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES["errors"], ids=lambda value: value["code"])
async def test_graph_checkpoint_preserves_fixed_native_error_codes(case):
    session = RecoveryHostSession("http://localhost:1", "synthetic-credential",
        {"inspect": b"{}"}, transport=httpx.MockTransport(
            lambda _: httpx.Response(case["status"], text=case["code"])))
    app = graph(session)
    config = {"configurable": {"thread_id": "public-response-test"}}
    result = await app.ainvoke({"choice": "inspect"}, config)
    assert result["recovery"]["error_code"] == case["code"]
    assert (await app.aget_state(config)).values["recovery"] == result["recovery"]
    assert set(result["recovery"]) == {"category", "error_code"}
    assert session.attempts == 1


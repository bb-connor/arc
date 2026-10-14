"""Actual StateGraph checkpoints retain categories, never protected native results."""
import json
from typing import TypedDict
import httpx
import pytest
from langgraph.graph import END, START, StateGraph
from langgraph.checkpoint.memory import InMemorySaver
from chio_sdk.recovery_host import RecoveryHostSession
from chio_langgraph.recovery import recovery_node


class State(TypedDict):
    choice: str
    recovery: dict[str, str]


@pytest.mark.asyncio
async def test_recovery_graph_reauthorizes_exact_replay_and_hides_canaries():
    wires = []
    revoked = False
    command = b'{"command":{"kind":"inspect_workflow","workflow_id":"opaque-workflow"},"command_id":"native-stable-command","schema":"chio.recovery.command.v1","version":1}'
    def native(request):
        wires.append(json.loads(request.content))
        if revoked:
            return httpx.Response(403, text="credential-canary private-provider-error")
        return httpx.Response(200, json={"status":{
            "command_id":"native-stable-command","workflow_id":"opaque-workflow","revision":1,
            "control":"active","effect":{"kind":"never_admitted"},"release":{"kind":"not_available"}},
            "original_response":{"receipt":{},"result":{"secret":"protected-result-canary"}}})
    # The full real receipt schema is supplied from the shared positive corpus.
    from pathlib import Path
    root = Path(__file__).resolve().parents[4]
    corpus = json.loads((root / "spec/vectors/recovery/v1/authority-contracts.json").read_text())
    positive = json.loads(next(row["wire"] for row in corpus["vectors"] if row["contract"] == "command_result" and row["valid"]))
    positive["status"]["command_id"] = "native-stable-command"
    positive["status"]["workflow_id"] = "opaque-workflow"
    positive["original_response"]["result"] = {"secret":"protected-result-canary"}
    def transport(request):
        if revoked:
            return native(request)
        wires.append(json.loads(request.content))
        return httpx.Response(200, json=positive)
    session = RecoveryHostSession("http://localhost:1", "credential-canary", {"resume":command},
                                  transport=httpx.MockTransport(transport), max_tool_actions=2)
    graph = StateGraph(State)
    graph.add_node("recovery", recovery_node(session))
    graph.add_edge(START, "recovery")
    graph.add_edge("recovery", END)
    app = graph.compile(checkpointer=InMemorySaver())
    config = {"configurable":{"thread_id":"public-trial"}}
    first = await app.ainvoke({"choice":"resume"}, config)
    assert first["recovery"]["workflow_id"] == "opaque-workflow"
    assert "canary" not in json.dumps(app.get_state(config).values)
    revoked = True
    second = await app.ainvoke({"choice":"resume"}, config)
    assert second["recovery"]["category"] == "refused"
    assert len(wires) == 2
    assert all(row["command"].encode() == command for row in wires)
    assert "canary" not in json.dumps(app.get_state(config).values)
    exhausted = await app.ainvoke({"choice":"resume"}, config)
    assert exhausted["recovery"]["category"] == "budget_exhausted"
    assert len(wires) == 2

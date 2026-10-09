"""The real framework tool retains closed native metadata without raw results."""
import asyncio
import json
from pathlib import Path

import httpx
import pytest

from chio_crewai.recovery import RecoveryTool
from chio_sdk.recovery_host import RecoveryHostSession

ROOT = Path(__file__).resolve().parents[4]
CASES = json.loads((ROOT / "sdks/tests/recovery-response-states.json").read_text())


@pytest.mark.parametrize("effect", CASES["effects"], ids=lambda value: value["kind"])
@pytest.mark.parametrize("mode", ["sync", "async"])
def test_framework_tool_preserves_native_state_dimensions(effect, mode):
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
    tool = RecoveryTool(session=session)
    result = (tool.to_structured_tool().invoke({"choice": "inspect"}) if mode == "sync"
              else asyncio.run(tool._arun("inspect")))
    saved = json.loads(result)
    assert saved == {"category": "quarantined", "command_id": response["status"]["command_id"],
                     "workflow_id": response["status"]["workflow_id"], "effect": effect["kind"],
                     "control": "quarantined", "release": "withheld"}
    assert "canary" not in result and "synthetic-credential" not in result
    assert len(calls) == session.attempts == 1


@pytest.mark.parametrize("case", CASES["errors"], ids=lambda value: value["code"])
def test_framework_tool_preserves_fixed_native_error_codes(case):
    session = RecoveryHostSession("http://localhost:1", "synthetic-credential",
        {"inspect": b"{}"}, transport=httpx.MockTransport(
            lambda _: httpx.Response(case["status"], text=case["code"])))
    result = json.loads(RecoveryTool(session=session).to_structured_tool().invoke({"choice": "inspect"}))
    assert result["error_code"] == case["code"]
    assert set(result) == {"category", "error_code"}
    assert session.attempts == 1


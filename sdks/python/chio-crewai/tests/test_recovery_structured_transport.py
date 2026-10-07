"""Framework metadata is discarded before bounded native choice dispatch."""
import json

import httpx
import pytest

from chio_crewai.recovery import RecoveryChoice, RecoveryTool
from chio_sdk.recovery_host import RecoveryHostSession


def tool_and_wires():
    wires = []
    def observe(request):
        wires.append(json.loads(request.content))
        return httpx.Response(403, text="provider-denial-canary")
    session = RecoveryHostSession("http://localhost:1", "owned-native-capability",
                                  {"resume": b'{"command_id":"owned-command"}'},
                                  transport=httpx.MockTransport(observe), max_tool_actions=1)
    return RecoveryTool(session=session), session, wires


@pytest.mark.parametrize("as_string", [False, True])
def test_reserved_framework_context_never_changes_the_native_actor_or_selected_bytes(as_string):
    tool, session, wires = tool_and_wires()
    structured = tool.to_structured_tool()
    arguments = {"choice": "resume", "security_context": {
        "agent_fingerprint": {"uuid": "synthetic", "metadata": {"capability": "forged-context-capability"}},
        "task_fingerprint": {"uuid": "synthetic-task"}}}
    supplied = json.dumps(arguments) if as_string else arguments
    result = structured.invoke(supplied)
    assert json.loads(result) == {"category": "refused"}
    assert session.attempts == len(wires) == 1
    assert wires[0]["capability"] == "owned-native-capability"
    assert wires[0]["command"] == '{"command_id":"owned-command"}'
    assert "fingerprint" not in result and "forged" not in result
    assert set(RecoveryChoice.model_json_schema()["properties"]) == {"choice"}
    assert RecoveryChoice.model_json_schema()["additionalProperties"] is False
    assert structured._original_tool is tool
    assert structured.current_usage_count == tool.current_usage_count == 1
    assert structured.max_usage_count == tool.max_usage_count == 8
    assert structured.result_as_answer is tool.result_as_answer is True
    assert arguments["security_context"]["agent_fingerprint"]["metadata"]["capability"] == "forged-context-capability"


def test_reserved_framework_context_is_never_inspected():
    class OpaqueContext:
        def __repr__(self):
            raise AssertionError("framework context was inspected")
        def __iter__(self):
            raise AssertionError("framework context was traversed")
    tool, session, wires = tool_and_wires()
    result = tool.to_structured_tool().invoke({"choice": "resume", "security_context": OpaqueContext()})
    assert json.loads(result) == {"category": "refused"}
    assert session.attempts == len(wires) == 1


@pytest.mark.parametrize("arguments", [
    {"choice": "resume", "unexpected": "untrusted"},
    {"choice": "resume", "security_context": {}, "unexpected": "untrusted"},
    {"choice": 1}, {"choice": True}, {"choice": "x" * 65},
    json.dumps({"choice": "resume", "security_context": "x" * 32768}),
])
def test_invalid_or_overlarge_choices_refuse_before_native_transport(arguments):
    tool, session, wires = tool_and_wires()
    with pytest.raises(ValueError):
        tool.to_structured_tool().invoke(arguments)
    assert not wires and session.attempts == 0


def test_mapping_subclasses_are_refused_before_custom_methods_or_native_transport():
    class CustomMapping(dict):
        def __iter__(self):
            raise AssertionError("custom mapping iteration")
        def __getitem__(self, key):
            raise AssertionError("custom mapping lookup")
    tool, session, wires = tool_and_wires()
    with pytest.raises(ValueError):
        tool.to_structured_tool().invoke(CustomMapping(choice="resume"))
    assert not wires and session.attempts == 0

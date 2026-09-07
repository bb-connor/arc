"""Known-response recovery and the native worker's authority/data boundaries."""

import copy
import io
import json

import pytest
from chio_mini_swe import ChioAgent, ChioEnvironment, ChioModel, ChioModelError
from chio_mini_swe.gateway import serve
from chio_mini_swe.model import RESULT_SCHEMA
from chio_mini_swe.state import encode
from chio_mini_swe.worker import SCHEMA, build_agent, export_result, run_bootstrap
from minisweagent.models.test_models import make_toolcall_output
from test_recovery import MemoryProcess


def message(command, cost=0.25):
    value = make_toolcall_output(
        "Act",
        [
            {
                "id": "call-1",
                "type": "function",
                "function": {"name": "bash", "arguments": json.dumps({"command": command})},
            }
        ],
        [{"command": command, "tool_call_id": "call-1"}],
    )
    value["extra"]["cost"] = cost
    return {"schema": RESULT_SCHEMA, "model_id": "fixture", "kind": "message", "message": value}


FINISH = message("COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\ndone")


class GatewayProcess(MemoryProcess):
    def __init__(self, responses):
        super().__init__()
        self.responses = responses
        self.provider_calls = 0
        self.model_fault = None
        self.unknown = False

    def invoke(self, key, server, tool, arguments, *, known_outcome_only=False):
        if server != "model":
            assert not known_outcome_only
            return super().invoke(key, server, tool, arguments)
        assert known_outcome_only, "model query permitted unknown-outcome redispatch"
        payload = encode([server, tool, arguments, known_outcome_only])
        if key in self.operations:
            previous, result = self.operations[key]
            assert previous == payload
            return result
        value = self.responses[self.provider_calls]
        self.provider_calls += 1
        result = {
            "verdict": "allow",
            "terminal_state": {"state": "unknown" if self.unknown else "completed"},
            "receipt_json": json.dumps({"model_operation": key}),
            "output": {
                "kind": "value",
                "value": {
                    "structuredContent": value,
                    "content": [{"type": "text", "text": "model response"}],
                },
            },
        }
        self.operations[key] = (payload, result)
        if self.model_fault is not None:
            error, self.model_fault = self.model_fault, None
            raise error
        return result


def agent(client, **model_overrides):
    model = ChioModel(
        client,
        **(
            {"server_id": "model", "tool_name": "model_infer", "model_id": "fixture"}
            | model_overrides
        ),
    )
    return ChioAgent(
        model,
        ChioEnvironment(client, server_id="sandbox", tool_name="execute", template_vars={}),
        run_id="repair",
        model_id="fixture",
        system_template="Repair it",
        instance_template="{{task}}",
        step_limit=8,
        cost_limit=5,
    )


@pytest.mark.parametrize("fault", [RuntimeError("lost reply"), KeyboardInterrupt()])
def test_completed_model_response_replays_without_another_query_or_charge(fault):
    client = GatewayProcess([message("append"), FINISH])
    client.model_fault = fault
    with pytest.raises(type(fault)):
        agent(client).run("Task")
    resumed = agent(client)
    assert resumed.run("Task")["submission"] == "done"
    assert client.provider_calls == resumed.n_calls == 2
    assert resumed.cost == 0.5
    assert len(resumed.model.receipts) == 2
    assert client.effects == ["append", "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\ndone"]
    assert agent(client).run("Task")["submission"] == "done"
    assert client.provider_calls == 2


def test_unknown_model_outcome_stops_every_attempt_without_commands_or_regeneration():
    client = GatewayProcess([FINISH])
    client.unknown = True
    for _ in range(2):
        with pytest.raises(ChioModelError, match="unknown"):
            agent(client).run("Task")
    assert client.provider_calls == 1
    assert not client.effects


def test_model_route_and_format_configuration_cannot_change_on_resume():
    client = GatewayProcess([FINISH])
    agent(client).run("Task")
    for override in [
        {"server_id": "other"},
        {"tool_name": "other"},
        {"observation_template": "{{output.output}}"},
    ]:
        with pytest.raises(RuntimeError, match="configuration changed"):
            agent(client, **override).run("Task")
    assert client.provider_calls == 1


@pytest.mark.parametrize("mutation", ["command", "role", "cost", "empty", "duplicate"])
def test_invalid_provider_decision_never_reaches_execution(mutation):
    response = copy.deepcopy(FINISH)
    value = response["message"]
    if mutation == "command":
        value["extra"]["actions"][0]["command"] = "different"
    elif mutation == "role":
        value["role"] = "exit"
    elif mutation == "cost":
        value["extra"]["cost"] = True
    elif mutation == "empty":
        value["extra"]["actions"] = []
    else:
        value["tool_calls"] *= 2
        value["extra"]["actions"] *= 2
    client = GatewayProcess([response])
    for _ in range(2):
        with pytest.raises(ChioModelError):
            agent(client).run("Task")
    assert client.provider_calls == 1
    assert not client.effects


def test_format_errors_preserve_upstream_cost_and_completion_behavior():
    invalid = {
        "schema": RESULT_SCHEMA,
        "model_id": "fixture",
        "kind": "format_error",
        "messages": [{"role": "user", "content": "Use a bash tool call", "extra": {"cost": 0.5}}],
    }
    client = GatewayProcess([invalid, FINISH])
    instance = agent(client)
    assert instance.run("Task")["exit_status"] == "Submitted"
    assert instance.cost == 0.75 and instance.n_calls == 2
    assert len(instance.model.receipts) == 2
    completed = export_result(client)
    assert completed["model_cost"] == 0.75 and len(completed["model_receipts"]) == 2


def bootstrap():
    return {
        "schema": "chio.process.worker-bootstrap.v1",
        "attempt": 55,
        "connection": {
            "protocol": "chio.process.v1",
            "socket_path": "/private/worker.sock",
            "credential": "private-test-value",
            "tools": [
                {"server_id": "model", "tool_name": "model_infer"},
                {"server_id": "sandbox", "tool_name": "execute"},
            ],
        },
        "input": {
            "schema": SCHEMA,
            "run_id": "repair",
            "task": "Task",
            "model": {"server_id": "model", "tool_name": "model_infer", "model_id": "fixture"},
            "environment": {"server_id": "sandbox", "tool_name": "execute", "template_vars": {}},
            "agent": {
                "system_template": "Repair it",
                "instance_template": "{{task}}",
                "step_limit": 8,
                "cost_limit": 5,
                "wall_time_limit_seconds": 300,
            },
        },
    }


def test_multiple_format_observations_cannot_hide_additional_provider_cost():
    client = GatewayProcess(
        [
            {
                "schema": RESULT_SCHEMA,
                "model_id": "fixture",
                "kind": "format_error",
                "messages": [{"role": "user", "content": "Retry", "extra": {"cost": 0.5}}] * 2,
            }
        ]
    )
    for _ in range(2):
        with pytest.raises(ChioModelError, match="format error"):
            agent(client).run("Task")
    assert client.provider_calls == 1
    assert not client.effects


def test_native_worker_keeps_full_result_in_checkpoint_and_emits_a_bounded_locator(monkeypatch):
    submission = "result" * 1000
    client = GatewayProcess([message("COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\n" + submission)])
    monkeypatch.setattr("chio_mini_swe.worker.ProcessClient", lambda *_: client)
    data = bootstrap()
    result = run_bootstrap(data)
    assert result["submission_truncated"]
    assert len(result["submission_preview"]) == 1024
    assert len(encode(result)) < 8192
    assert "private-test-value" not in json.dumps(result)
    assert export_result(client)["result"]["submission"] == submission
    assert "private-test-value" not in json.dumps(export_result(client))
    assert client.provider_calls == 1
    # Native attempt counters never participate in the model-operation identity.
    data["attempt"] += 1
    assert run_bootstrap(data) == result
    assert client.provider_calls == 1


@pytest.mark.parametrize("mutation", ["provider", "output_path", "limits", "route", "variables"])
def test_native_bootstrap_rejects_ambient_provider_config_and_ungranted_routes(mutation):
    data = bootstrap()
    if mutation == "provider":
        data["input"]["model"]["api_key"] = "must-not-be-accepted"
    elif mutation == "output_path":
        data["input"]["agent"]["output_path"] = "/host/admin.json"
    elif mutation == "limits":
        data["input"]["agent"]["step_limit"] = 0
    elif mutation == "variables":
        data["input"]["environment"]["template_vars"] = []
    else:
        data["connection"]["tools"] = []
    with pytest.raises(ValueError):
        build_agent(data)


def test_gateway_sanitizes_provider_errors_and_accepts_no_provider_overrides():
    class Provider:
        calls = 0

        def query(self, messages):
            self.calls += 1
            raise RuntimeError("provider-key-must-stay-private")

    provider = Provider()
    from chio_mini_swe.model import QUERY_SCHEMA

    arguments = {
        "schema": QUERY_SCHEMA,
        "model_id": "fixture",
        "turn": 1,
        "messages": [{"role": "user", "content": "Task"}],
    }
    frames = [
        {
            "jsonrpc": "2.0",
            "id": index,
            "method": "tools/call",
            "params": {"name": "model_infer", "arguments": value},
        }
        for index, value in enumerate([arguments, arguments | {"api_key": "other"}])
    ]
    output = io.StringIO()
    serve(
        provider,
        model_id="fixture",
        input_stream=io.BytesIO(b"".join(encode(frame) + b"\n" for frame in frames)),
        output_stream=output,
    )
    assert "provider-key-must-stay-private" not in output.getvalue()
    assert provider.calls == 1
    assert all(json.loads(line)["result"]["isError"] for line in output.getvalue().splitlines())

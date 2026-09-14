"""Exercise the installed upstream loop with a deterministic durable-store fixture."""

import hashlib
import json

import pytest
from chio_mini_swe import ChioAgent, ChioEnvironment, ChioExecutionError
from chio_mini_swe.state import encode
from minisweagent.exceptions import FormatError
from minisweagent.models.test_models import DeterministicModel, make_output


class MemoryProcess:
    def __init__(self):
        self.value = None
        self.revision = 0
        self.blobs = {}
        self.operations = {}
        self.effects = []
        self.interrupt = None
        self.denied = False

    def inspect(self):
        return {"checkpoint": {"revision": str(self.revision), "value": self.value}}

    def put_blob(self, data):
        key = hashlib.sha256(data).hexdigest()
        self.blobs[key] = data
        return {"sha256": key, "bytes": len(data)}

    def read_blob(self, key):
        return self.blobs[key]

    def checkpoint(self, revision, value):
        if revision != str(self.revision):
            raise RuntimeError("checkpoint conflict")
        self.revision += 1
        self.value = json.loads(encode(value))
        return {"revision": str(self.revision), "value": self.value}

    def invoke(self, key, server, tool, arguments):
        payload = encode([server, tool, arguments])
        if key in self.operations:
            previous, result = self.operations[key]
            if payload != previous:
                raise RuntimeError("operation conflict")
            return result
        command = arguments["command"]
        self.effects.append(command)
        result = {
            "verdict": "deny" if self.denied else "allow",
            "terminal_state": {"state": "completed"},
            "receipt_json": json.dumps({"operation": key}),
            "output": {
                "kind": "value",
                "value": {"output": command, "returncode": 0, "exception_info": ""},
            },
        }
        self.operations[key] = (payload, result)
        if self.interrupt:
            error, self.interrupt = self.interrupt, None
            raise error
        return result


def response(*commands):
    return make_output("Act", [{"command": c} for c in commands], cost=0.25)


FINISH = response("COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\ndone")


class FaultModel(DeterministicModel):
    def query(self, messages, **kwargs):
        if self.fault is not None:
            fault, self.fault = self.fault, None
            raise fault
        return super().query(messages, **kwargs)


def agent(client, outputs, fault=None, **kwargs):
    model = FaultModel(outputs=outputs)
    model.fault = fault
    return ChioAgent(
        model,
        ChioEnvironment(client, server_id="sandbox", tool_name="execute", template_vars={}),
        run_id="repair-123",
        model_id="qualification-provider",
        system_template="Repair the repository",
        instance_template="{{task}}",
        **({"step_limit": 10, "cost_limit": 5} | kwargs),
    )


@pytest.mark.parametrize("error", [RuntimeError("lost reply"), KeyboardInterrupt()])
def test_completed_command_recovery_keeps_response_and_distinct_identical_commands(error):
    client = MemoryProcess()
    client.interrupt = error
    first = agent(client, [response("append", "append")])
    with pytest.raises(type(error)):
        first.run("Fix it")
    assert first.n_calls == 1
    resumed = agent(client, [response("append"), FINISH])
    assert resumed.run("Fix it")["submission"] == "done"
    assert client.effects == [
        "append",
        "append",
        "append",
        "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\ndone",
    ]
    assert resumed.n_calls == 3
    assert resumed.cost == 0.75
    assert len(set(resumed.env.receipts)) == 4
    complete = agent(client, [])
    assert complete.run("Fix it")["submission"] == "done"
    assert complete.model.current_index == -1
    assert complete.env.receipts == resumed.env.receipts
    with pytest.raises(RuntimeError, match="fresh ChioAgent"):
        complete.run("Another task")


def test_lost_model_response_stops_without_new_provider_request():
    client = MemoryProcess()
    first = agent(client, [], fault=RuntimeError("provider disconnected"))
    with pytest.raises(RuntimeError, match="provider disconnected"):
        first.run("Fix it")
    resumed = agent(client, [FINISH])
    with pytest.raises(RuntimeError, match="Provider response is unknown"):
        resumed.run("Fix it")
    assert resumed.model.current_index == -1
    assert client.effects == []


def test_changed_task_and_stale_writer_refuse_before_dispatch():
    client = MemoryProcess()
    stale = agent(client, [FINISH])
    current = agent(client, [FINISH])
    current.run("Fix it")
    with pytest.raises(RuntimeError, match="checkpoint conflict"):
        stale.run("Fix it")
    changed = agent(client, [FINISH])
    with pytest.raises(RuntimeError, match="configuration changed"):
        changed.run("Do something else")
    assert len(client.effects) == 1
    assert stale.model.current_index == changed.model.current_index == -1


def test_denial_cannot_become_an_observation_or_replanning_request():
    client = MemoryProcess()
    client.denied = True
    first = agent(client, [response("forbidden"), FINISH])
    with pytest.raises(ChioExecutionError, match="denied") as error:
        first.run("Fix it")
    resumed = agent(client, [FINISH])
    with pytest.raises(ChioExecutionError, match="denied") as again:
        resumed.run("Fix it")
    assert error.value.receipt_json == again.value.receipt_json
    assert resumed.model.current_index == -1
    assert client.effects == ["forbidden"]


def test_upstream_format_error_cost_limit_and_completion_semantics_survive():
    client = MemoryProcess()
    bad = FormatError({"role": "user", "content": "Bad format", "extra": {"cost": 0.5}})
    instance = agent(client, [FINISH], fault=bad)
    assert instance.run("Fix it")["exit_status"] == "Submitted"
    assert instance.cost == 0.75
    assert instance.n_calls == 2
    assert instance.messages[2]["content"] == "Bad format"
    # Upstream resets the counter after a clean step, not a Submitted interrupt.
    assert instance.n_consecutive_format_errors == 1
    completed = agent(client, [])
    assert completed.run("Fix it")["exit_status"] == "Submitted"
    assert completed.n_consecutive_format_errors == 1


def test_missing_blob_and_unbound_environment_fail_closed():
    client = MemoryProcess()
    instance = agent(client, [FINISH])
    with pytest.raises(ChioExecutionError, match="outside"):
        instance.env.execute({"command": "append"})
    instance.run("Fix it")
    client.blobs.clear()
    with pytest.raises(KeyError):
        agent(client, [FINISH]).run("Fix it")
    assert len(client.effects) == 1


def test_unknown_tool_outcome_stops_without_replanning():
    client = MemoryProcess()
    client.interrupt = RuntimeError("lost reply")
    with pytest.raises(RuntimeError, match="lost reply"):
        agent(client, [response("append")]).run("Fix it")
    _, stored = next(iter(client.operations.values()))
    stored["terminal_state"] = {"state": "unknown"}
    resumed = agent(client, [FINISH])
    with pytest.raises(ChioExecutionError, match="unknown"):
        resumed.run("Fix it")
    assert client.effects == ["append"]
    assert resumed.model.current_index == -1


def test_cost_and_step_limits_survive_an_interrupted_command():
    for limits in [{"cost_limit": 0.5}, {"step_limit": 2}]:
        client = MemoryProcess()
        client.interrupt = KeyboardInterrupt()
        with pytest.raises(KeyboardInterrupt):
            agent(client, [response("append")], **limits).run("Fix it")
        resumed = agent(client, [response("append"), FINISH], **limits)
        assert resumed.run("Fix it")["exit_status"] == "LimitsExceeded"
        assert resumed.n_calls == 2
        assert resumed.cost == 0.5
        assert client.effects == ["append", "append"]


def test_concurrent_recovery_cannot_query_another_provider():
    client = MemoryProcess()
    client.interrupt = RuntimeError("lost reply")
    with pytest.raises(RuntimeError, match="lost reply"):
        agent(client, [response("append")]).run("Fix it")
    first = agent(client, [FINISH])
    second = agent(client, [FINISH])
    first.run("Fix it")
    with pytest.raises(RuntimeError, match="checkpoint conflict"):
        second.run("Fix it")
    assert second.model.current_index == -1
    assert client.effects == ["append", "COMPLETE_TASK_AND_SUBMIT_FINAL_OUTPUT\ndone"]


@pytest.mark.parametrize("is_error", [False, True])
def test_native_mcp_envelope_preserves_success_and_refuses_error_flag(is_error):
    client = MemoryProcess()
    client.interrupt = RuntimeError("lost reply")
    with pytest.raises(RuntimeError, match="lost reply"):
        agent(client, [response("append")]).run("Fix it")
    _, stored = next(iter(client.operations.values()))
    stored["output"]["value"] = {
        "isError": is_error,
        "content": [],
        "structuredContent": stored["output"]["value"],
    }
    resumed = agent(client, [FINISH])
    if is_error:
        with pytest.raises(ChioExecutionError, match="MCP execution failed"):
            resumed.run("Fix it")
        assert resumed.model.current_index == -1
    else:
        assert resumed.run("Fix it")["exit_status"] == "Submitted"
    assert client.effects.count("append") == 1


def test_invalid_later_action_refuses_the_whole_batch():
    client = MemoryProcess()
    instance = agent(client, [make_output("Act", [{"command": "append"}, {}])])
    with pytest.raises(ChioExecutionError, match="invalid command batch"):
        instance.run("Fix it")
    assert client.effects == []

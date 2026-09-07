"""Native runner entrypoint; both model queries and commands use scoped Chio RPC."""

import json
import math
import sys

from chio_process import ProcessClient

from chio_mini_swe import ChioAgent, ChioEnvironment, ChioModel
from chio_mini_swe.state import Journal

SCHEMA = "chio.mini-swe.worker.v1"
MAX_BOOTSTRAP_BYTES = 1024 * 1024
AGENT_FIELDS = {
    "system_template",
    "instance_template",
    "step_limit",
    "cost_limit",
    "wall_time_limit_seconds",
    "max_consecutive_format_errors",
}


def load_bootstrap(stream):
    data = stream.read(MAX_BOOTSTRAP_BYTES + 1)
    if len(data) > MAX_BOOTSTRAP_BYTES:
        raise ValueError("Native mini-SWE bootstrap exceeds one MiB")
    return json.loads(data)


def validate_bootstrap(bootstrap):
    """Validate configuration without connecting to a worker socket or provider."""
    if (
        not isinstance(bootstrap, dict)
        or bootstrap.get("schema") != "chio.process.worker-bootstrap.v1"
    ):
        raise ValueError("Expected a native Chio worker bootstrap")
    data, connection = bootstrap.get("input"), bootstrap.get("connection")
    if (
        not isinstance(data, dict)
        or data.get("schema") != SCHEMA
        or set(data) != {"schema", "run_id", "task", "model", "environment", "agent"}
        or not isinstance(connection, dict)
        or connection.get("protocol") != "chio.process.v1"
    ):
        raise ValueError("Invalid native mini-SWE configuration")
    if (
        not isinstance(data["task"], str)
        or not data["task"].strip()
        or len(data["task"].encode()) > 128 * 1024
    ):
        raise ValueError("A bounded, non-empty task is required")
    config = data["agent"]
    if not isinstance(config, dict) or set(config) - AGENT_FIELDS:
        raise ValueError("Only native agent prompt and limit settings are allowed")
    if (
        type(config.get("step_limit")) is not int
        or not 1 <= config["step_limit"] <= 256
        or type(config.get("cost_limit")) not in (int, float)
        or not math.isfinite(config["cost_limit"])
        or not 0 < config["cost_limit"] <= 1000
        or type(config.get("wall_time_limit_seconds")) is not int
        or not 1 <= config["wall_time_limit_seconds"] <= 86400
    ):
        raise ValueError("Explicit positive step, cost and total wall-clock limits are required")
    for key, allowed, required in [
        (
            "model",
            {"server_id", "tool_name", "model_id", "observation_template"},
            {"server_id", "tool_name", "model_id"},
        ),
        (
            "environment",
            {"server_id", "tool_name", "template_vars"},
            {"server_id", "tool_name", "template_vars"},
        ),
    ]:
        route = data[key]
        if not isinstance(route, dict) or set(route) - allowed or not required <= set(route):
            raise ValueError("Invalid host-selected model or execution route")
        if not any(
            tool.get("server_id") == route["server_id"]
            and tool.get("tool_name") == route["tool_name"]
            for tool in connection.get("tools", [])
            if isinstance(tool, dict)
        ):
            raise ValueError("Selected route is absent from this process's connection")
    if not isinstance(data["environment"]["template_vars"], dict):
        raise ValueError("Environment template variables must be an object")
    if (
        not isinstance(data["run_id"], str)
        or not data["run_id"].strip()
        or len(data["run_id"].encode()) > 1024
    ):
        raise ValueError("A stable bounded run identity is required")
    from minisweagent.agents.default import AgentConfig

    AgentConfig(output_path=None, **config)
    # These route adapters only validate and retain their constructor values.
    # Creating ChioAgent would read its journal, so it belongs to build_agent.
    ChioModel(None, **data["model"])
    ChioEnvironment(None, **data["environment"])
    return data, connection


def build_agent(bootstrap):
    """Build an upstream loop from a native bootstrap without ambient provider access."""
    data, connection = validate_bootstrap(bootstrap)
    client = ProcessClient(connection["socket_path"], connection["credential"])
    model = ChioModel(client, **data["model"])
    environment = ChioEnvironment(client, **data["environment"])
    return ChioAgent(
        model,
        environment,
        run_id=data["run_id"],
        model_id=model.model_id,
        output_path=None,
        **data["agent"],
    )


def run_bootstrap(bootstrap, *, agent=None):
    """Run one native attempt and return a bounded result locator for retained logs."""
    if agent is None:
        agent = build_agent(bootstrap)
    result = agent.run(bootstrap["input"]["task"])
    submission = result.get("submission", "")
    if not isinstance(submission, str):
        raise ValueError("Invalid mini-SWE submission")
    return {
        "schema": "chio.mini-swe.worker-result.v1",
        "exit_status": result.get("exit_status"),
        "submission_preview": submission[:1024],
        "submission_truncated": len(submission) > 1024,
        "checkpoint": agent.journal.reference,
        "model_calls": agent.n_calls,
        "model_cost": agent.cost,
        "model_receipts": len(agent.model.receipts),
        "command_receipts": len(agent.env.receipts),
    }


def export_result(client):
    """Read the full completed trajectory and original receipts without invoking a tool."""
    snapshot = Journal(client).read()
    if (
        snapshot is None
        or snapshot.get("phase") != "ready"
        or snapshot["messages"][-1].get("role") != "exit"
    ):
        raise RuntimeError("mini-SWE task has no completed result")
    return {
        "schema": "chio.mini-swe.result.v1",
        "result": snapshot["messages"][-1].get("extra", {}),
        "model_calls": snapshot["n_calls"],
        "model_cost": snapshot["cost"],
        "messages": snapshot["messages"],
        "command_receipts": snapshot["receipts"],
        "model_receipts": snapshot.get("model_receipts", []),
    }


def main():
    result = run_bootstrap(load_bootstrap(sys.stdin.buffer))
    print(json.dumps(result), flush=True)
    return 0 if result["exit_status"] == "Submitted" else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Preparation must bind task inputs and preserve incomplete native initialization."""

import json

import pytest
from chio_mini_swe.operator import prepare, prepared
from test_provider import config


@pytest.fixture
def profile(tmp_path, monkeypatch):
    binary = tmp_path / "chio"
    binary.write_text("#!/bin/sh\nexit 1\n")
    binary.chmod(0o700)
    (tmp_path / "provider.json").write_text(json.dumps(config()))
    (tmp_path / "policy.yaml").write_text("operator policy")
    (tmp_path / "launch.json").write_text("signed operator policy")
    tools = [
        {"server_id": "model", "tool_name": "model_infer"},
        {"server_id": "sandbox", "tool_name": "execute"},
    ]
    (tmp_path / "host.json").write_text(
        json.dumps(
            {
                "schema": "chio.process.host.v1",
                "policy": "policy.yaml",
                "servers": [
                    {
                        "id": name,
                        "command": [str(binary)],
                        "launch_policy": "launch.json",
                        "launch_policy_signer": "pinned",
                    }
                    for name in ("model", "sandbox")
                ],
                "children": [{"id": "coder", "tools": tools}],
            }
        )
    )
    value = {
        "schema": "chio.mini-swe.operator.v1",
        "chio": str(binary),
        "host_config": "host.json",
        "provider_config": "provider.json",
        "process": "coder",
        "worker_image": "sha256:" + "a" * 64,
        "model_server": "model",
        "execution": tools[1],
        "environment": {},
        "agent": {
            "system_template": "Repair it",
            "instance_template": "{{task}}",
            "step_limit": 8,
            "cost_limit": 1,
            "wall_time_limit_seconds": 300,
        },
        "max_attempts": 2,
        "timeout_seconds": 30,
    }
    path = tmp_path / "profile.json"
    path.write_text(json.dumps(value))
    (tmp_path / "task.md").write_text("Fix it")
    calls = []

    def initialize(*arguments, **_kwargs):
        calls.append(arguments)
        return {"kernel_key": "pinned-kernel-key"}

    monkeypatch.setattr("chio_mini_swe.operator.command", initialize)
    monkeypatch.setattr("chio_mini_swe.operator.supports_state_reader", lambda _: True)
    return tmp_path, path, calls


def test_provider_change_blocks_running_but_not_reading_retained_results(profile):
    root, path, calls = profile
    value = prepare(path, root / "task.md", root / "run")
    assert len(calls) == 1
    assert prepared(root / "run", running=True)[1]["model_id"] == value["model_id"]
    (root / "provider.json").write_text(json.dumps(config() | {"model": "changed"}))
    with pytest.raises(ValueError, match="Provider configuration changed"):
        prepared(root / "run", running=True)
    (root / "provider.json").unlink()
    assert prepared(root / "run")[1]["model_id"] == value["model_id"]
    assert len(calls) == 1


@pytest.mark.parametrize("changed", ["binary", "plan", "manifest"])
def test_prepared_artifact_changes_cannot_reinterpret_the_task(profile, changed):
    root, path, calls = profile
    prepare(path, root / "task.md", root / "run")
    if changed == "binary":
        (root / "chio").write_text("#!/bin/sh\nexit 0\n")
    elif changed == "plan":
        (root / "run/plan.json").write_text("{}")
    else:
        record = json.loads((root / "run/prepared.json").read_text())
        record["files"] = {}
        (root / "run/prepared.json").write_text(json.dumps(record))
    with pytest.raises(ValueError):
        prepared(root / "run", running=True)
    assert len(calls) == 1


def test_failed_initialization_preserves_partial_state_without_a_ready_marker(profile, monkeypatch):
    root, path, _ = profile

    def failed(*_, **_kwargs):
        raise RuntimeError("interrupted initialization")

    monkeypatch.setattr("chio_mini_swe.operator.command", failed)
    with pytest.raises(RuntimeError, match="interrupted"):
        prepare(path, root / "task.md", root / "run")
    assert (root / "run/plan.json").is_file() and not (root / "run/prepared.json").exists()
    with pytest.raises(FileExistsError):
        prepare(path, root / "task.md", root / "run")


def test_old_host_is_refused_before_task_initialization(profile, monkeypatch):
    root, path, calls = profile
    monkeypatch.setattr("chio_mini_swe.operator.supports_state_reader", lambda _: False)
    with pytest.raises(ValueError, match="administrative process state reads"):
        prepare(path, root / "task.md", root / "run")
    assert not calls and not (root / "run").exists()


@pytest.mark.parametrize(
    "invalid", ["writable_binary", "missing_policy", "task_limit", "worker_config"]
)
def test_invalid_configuration_stops_before_native_initialization(profile, invalid):
    root, path, calls = profile
    if invalid == "writable_binary":
        (root / "chio").chmod(0o770)
    elif invalid == "missing_policy":
        host = json.loads((root / "host.json").read_text())
        del host["servers"][0]["launch_policy"]
        (root / "host.json").write_text(json.dumps(host))
    elif invalid == "task_limit":
        (root / "task.md").write_bytes(b"a" * (128 * 1024 + 1))
    else:
        value = json.loads(path.read_text())
        value["agent"]["output_path"] = "/host/file"
        path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        prepare(path, root / "task.md", root / "run")
    assert not calls and not (root / "run").exists()

"""Session authority handoff, immutable inputs and native lifecycle exclusion."""

import copy
import fcntl
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from chio_mini_swe import repository_container, repository_store, session, session_security
from chio_mini_swe.repository_archive import git
from test_provider import config as provider_config
from test_repository import commit


@pytest.fixture
def setup(tmp_path, monkeypatch):
    prior = os.umask(0o077)
    monkeypatch.setenv("MSWEA_GLOBAL_CONFIG_DIR", str(tmp_path / "mini-config"))
    monkeypatch.setenv("MSWEA_SILENT_STARTUP", "1")
    source = tmp_path / "source"
    source.mkdir()
    git("init", "--quiet", cwd=source)
    (source / "file").write_text("committed contents\n")
    commit(source)
    binary = tmp_path / "chio"
    binary.write_text("#!/bin/sh\nexit 1\n")
    binary.chmod(0o700)
    launchers = {}
    for name in ("chio-mini-swe", "chio-mini-swe-model", "chio-mini-swe-repository"):
        path = tmp_path / name
        path.write_text("#!/bin/sh\nexit 1\n")
        path.chmod(0o700)
        launchers[name] = {"path": str(path), "sha256": "0" * 64}
    environment = {"prefix": str(tmp_path), "launchers": launchers, "sources": {"fixture": "0"}}
    monkeypatch.setattr(
        session_security, "environment_identity", lambda: copy.deepcopy(environment)
    )
    monkeypatch.setattr(session.operator, "supports_state_reader", lambda _: True)
    monkeypatch.setattr(repository_store, "engine", lambda: "fixture-engine")
    monkeypatch.setattr(repository_store, "qualify_image", lambda _: None)
    monkeypatch.setattr(repository_container, "qualify_image", lambda _: None)
    value = {
        "schema": session.CONFIG,
        "chio": str(binary),
        "repository": "source",
        "revision": "HEAD",
        "provider_config": "provider.json",
        "worker_image": "sha256:" + "1" * 64,
        "execution_image": "sha256:" + "2" * 64,
        "helper_image": "sha256:" + "3" * 64,
        "command_timeout_seconds": 20,
        "agent": {
            "system_template": "Repair the repository.",
            "instance_template": "{{task}}",
            "step_limit": 8,
            "cost_limit": 1,
            "wall_time_limit_seconds": 600,
        },
        "max_attempts": 2,
        "timeout_seconds": 240,
        "max_calls": 16,
        "capability_ttl_seconds": 3600,
    }
    (tmp_path / "config.json").write_text(json.dumps(value))
    provider = provider_config() | {"timeout_seconds": 90}
    (tmp_path / "provider.json").write_text(json.dumps(provider))
    (tmp_path / "task.md").write_text("Repair this repository")
    calls = []

    def prepare(profile, task, state):
        calls.append((profile, task, state, Path.cwd()))
        (state / "host").mkdir(parents=True)
        (state / "host/host.lock").touch(mode=0o600)
        return {"state": str(state)}

    monkeypatch.setattr(session.operator, "prepare", prepare)
    monkeypatch.setattr(session.operator, "prepared", lambda *_a, **_kw: None)
    try:
        yield tmp_path, value, environment, calls
    finally:
        os.umask(prior)


def initialize(setup):
    root, _, _, _ = setup
    state = root / "session"
    session.initialize(root / "config.json", root / "task.md", state)
    return state


def authorization(state):
    request = json.loads((state / "provisioning-request.json").read_text())
    bindings = {}
    for name, server in request["servers"].items():
        path = state.parent / (name + "-supplied-policy.json")
        path.write_text(
            json.dumps(
                {
                    "body": {
                        "runtime": {
                            "target_path": server["command"][0],
                            "target_argv": server["command"],
                            "working_directory": server["working_directory"],
                            "execution_identity": {
                                "uid": server["execution_uid"],
                                "gid": server["execution_gid"],
                            },
                        }
                    }
                }
            )
        )
        bindings[name] = {"launch_policy": str(path), "launch_policy_signer": "a" * 64}
    path = state.parent / "authorization.json"
    path.write_text(json.dumps({"schema": session.AUTHORIZATION, "servers": bindings}))
    return path


def test_initialization_emits_frozen_unsigned_inputs_before_native_authority(setup):
    root, _, _, calls = setup
    state = initialize(setup)
    request = json.loads((state / "provisioning-request.json").read_text())
    assert request["schema"] == session.REQUEST and set(request["servers"]) == {"model", "sandbox"}
    assert request["servers"]["model"]["request_timeout_seconds"] == 120
    assert request["servers"]["sandbox"]["request_timeout_seconds"] == 140
    assert request["servers"]["model"]["tools"][0]["name"] == "model_infer"
    assert request["servers"]["sandbox"]["tools"][0]["name"] == "execute"
    assert not calls and not (state / "run").exists() and not (state / "policy.yaml").exists()
    with pytest.raises(FileNotFoundError):
        session.run(state)
    assert not calls
    (root / "provider.json").unlink()
    (root / "task.md").unlink()
    assert session.inspect(state)["phase"] == "initialized"


def test_prepare_captures_explicit_policy_and_delegates_in_requested_directory(setup):
    _, _, _, calls = setup
    state = initialize(setup)
    path = authorization(state)
    before = Path.cwd()
    session.prepare(state, path)
    assert len(calls) == 1 and calls[0][3] == state and Path.cwd() == before
    host = json.loads((state / "host.json").read_text())
    assert host["limits"] == {"max_calls": 16, "max_depth": 1, "max_processes": 2}
    assert host["children"][0]["tools"] == session.ROUTES
    for server in host["servers"]:
        assert Path(server["launch_policy"]).parent == state
        assert server["launch_policy_signer"] == "a" * 64
    with pytest.raises(ValueError, match="already started"):
        session.prepare(state, path)
    assert len(calls) == 1


@pytest.mark.parametrize("mutation", ["server", "signer", "argv", "cwd", "uid"])
def test_policy_mismatch_stops_before_native_preparation(setup, mutation):
    _, _, _, calls = setup
    state = initialize(setup)
    path = authorization(state)
    value = json.loads(path.read_text())
    if mutation == "server":
        value["servers"]["other"] = value["servers"].pop("sandbox")
    elif mutation == "signer":
        value["servers"]["model"]["launch_policy_signer"] = "not-a-key"
    else:
        policy = Path(value["servers"]["model"]["launch_policy"])
        content = json.loads(policy.read_text())
        runtime = content["body"]["runtime"]
        if mutation == "argv":
            runtime["target_argv"].append("unrequested-argument")
        elif mutation == "cwd":
            runtime["working_directory"] = str(state.parent)
        else:
            runtime["execution_identity"]["uid"] += 1
        policy.write_text(json.dumps(content))
    path.write_text(json.dumps(value))
    with pytest.raises(ValueError):
        session.prepare(state, path)
    assert (
        not calls and not (state / "run").exists() and not (state / "authorization.json").exists()
    )


@pytest.mark.parametrize(
    "mutation", ["task", "provider", "configuration", "request", "binary", "package"]
)
def test_drift_cannot_reinterpret_initialized_session(setup, mutation):
    root, _, environment, calls = setup
    state = initialize(setup)
    path = authorization(state)
    if mutation == "package":
        environment["sources"]["fixture"] = "changed"
    else:
        target = (
            root / "chio"
            if mutation == "binary"
            else state
            / {
                "task": "task.md",
                "provider": "provider.json",
                "configuration": "configuration.json",
                "request": "provisioning-request.json",
            }[mutation]
        )
        target.write_bytes(target.read_bytes() + b" ")
    with pytest.raises(ValueError):
        session.prepare(state, path)
    assert not calls


@pytest.mark.parametrize("mutation", ["image", "calls", "attempt", "ttl", "agent"])
def test_invalid_limits_and_images_fail_before_state_creation(setup, mutation):
    root, value, _, calls = setup
    if mutation == "image":
        value["worker_image"] = "image:latest"
    elif mutation == "calls":
        value["max_calls"] = True
    elif mutation == "attempt":
        value["timeout_seconds"] = 60
    elif mutation == "ttl":
        value["capability_ttl_seconds"] = 120
    else:
        value["agent"]["output_path"] = "/unrequested/output"
    (root / "config.json").write_text(json.dumps(value))
    with pytest.raises(ValueError):
        initialize(setup)
    assert not calls and not (root / "session").exists()


def test_failed_native_prepare_retains_partial_state_without_ready_marker(setup, monkeypatch):
    state = initialize(setup)
    path = authorization(state)

    def interrupted(_profile, _task, run):
        (run / "host").mkdir(parents=True)
        (run / "host/host.lock").touch(mode=0o600)
        raise RuntimeError("native initialization failed")

    monkeypatch.setattr(session.operator, "prepare", interrupted)
    with pytest.raises(RuntimeError, match="native initialization failed"):
        session.prepare(state, path)
    assert not (state / "session-prepared.json").exists()
    assert session.inspect(state)["phase"] == "preparation_incomplete"
    with pytest.raises(ValueError, match="already started"):
        session.prepare(state, path)


def test_recover_and_result_refuse_a_held_native_lock_before_effects(setup, monkeypatch):
    state = initialize(setup)
    session.prepare(state, authorization(state))
    monkeypatch.setattr(session.operator, "result", lambda *_: pytest.fail("read before host lock"))
    with (state / "run/host/host.lock").open("rb") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            session.recover(state)
        with pytest.raises(BlockingIOError):
            session.result(state, state.parent / "result")
    assert not (state.parent / "result").exists()


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo", "missing"])
def test_host_lock_must_be_existing_private_regular_file(setup, kind):
    state = initialize(setup)
    session.prepare(state, authorization(state))
    lock = state / "run/host/host.lock"
    lock.unlink()
    if kind == "symlink":
        lock.symlink_to(state / "session.lock")
    elif kind == "hardlink":
        os.link(state / "session.lock", lock)
    elif kind == "fifo":
        os.mkfifo(lock)
    with pytest.raises((ValueError, OSError)):
        session.recover(state)


def test_offline_inspection_survives_provider_snapshot_removal(setup, monkeypatch):
    state = initialize(setup)
    session.prepare(state, authorization(state))
    (state / "provider.json").unlink()
    monkeypatch.setattr(session.operator, "command", lambda *_: {"offline": True})
    assert session.inspect(state)["host"] == {"offline": True}
    with pytest.raises(FileNotFoundError):
        session.run(state)


def test_foreign_owned_0755_ancestor_is_not_protected(tmp_path, monkeypatch):
    foreign = tmp_path / "foreign"
    foreign.mkdir()
    original = Path.lstat

    def metadata(path):
        if path == foreign:
            return SimpleNamespace(st_mode=0o40755, st_uid=os.getuid() + 10000)
        return original(path)

    monkeypatch.setattr(Path, "lstat", metadata)
    with pytest.raises(ValueError):
        session.operator.protected_parent(foreign)
    # Root-owned sticky temporary ancestry remains a supported deployment path.
    session.operator.protected_parent(tmp_path)


def test_session_run_executes_without_allocating_temporary_configuration(monkeypatch):
    class Executed(Exception):
        pass

    def run(state):
        assert state == "/private/session"
        raise Executed

    monkeypatch.setattr(session, "run", run)
    monkeypatch.setattr(session.operator.os, "umask", lambda _: None)
    monkeypatch.setattr(
        session.operator.tempfile,
        "TemporaryDirectory",
        lambda **_: pytest.fail("session exec allocated a temporary directory"),
    )
    monkeypatch.setattr(
        "sys.argv", ["chio-mini-swe", "session", "run", "--state", "/private/session"]
    )
    with pytest.raises(Executed):
        session.operator.main()

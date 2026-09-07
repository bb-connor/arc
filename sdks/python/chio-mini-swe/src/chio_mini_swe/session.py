"""Installed coding sessions with an explicit operator authorization handoff."""

import contextlib
import os
import re
from pathlib import Path

from chio_mini_swe import operator, session_security
from chio_mini_swe.provider_config import identity, validate
from chio_mini_swe.repository_archive import digest
from chio_mini_swe.repository_store import Workspace, atomic_bytes, configuration_digest

CONFIG = "chio.mini-swe.session-config.v1"
INITIALIZED = "chio.mini-swe.session-initialized.v1"
PREPARED = "chio.mini-swe.session-prepared.v1"
AUTHORIZATION = "chio.mini-swe.session-authorization.v1"
REQUEST = "chio.mini-swe.provisioning-request.v1"
ROUTES = [
    {"server_id": "model", "tool_name": "model_infer"},
    {"server_id": "sandbox", "tool_name": "execute"},
]
CONFIG_FIELDS = {
    "schema",
    "chio",
    "repository",
    "revision",
    "provider_config",
    "worker_image",
    "execution_image",
    "helper_image",
    "command_timeout_seconds",
    "agent",
    "max_attempts",
    "timeout_seconds",
    "max_calls",
    "capability_ttl_seconds",
}
INITIAL_FILES = {"configuration.json", "task.md", "provider.json", "provisioning-request.json"}
PREPARED_FILES = {
    "host.json",
    "operator.json",
    "policy.yaml",
    "model-launch-policy.json",
    "sandbox-launch-policy.json",
    "authorization.json",
}


def _fields(value, names):
    if not isinstance(value, dict) or set(value) != names:
        raise ValueError("Invalid coding session document fields")


def _integer(value, low, high):
    if type(value) is not int or not low <= value <= high:
        raise ValueError("Coding session limits must be bounded integers")


def _path(base, value):
    if not isinstance(value, str) or not value or "\0" in value:
        raise ValueError("Coding session paths must be nonempty strings")
    return (base / value).resolve(strict=True)


def _hashes(state, names):
    return {
        name: session_security.file_hash(state / name, private=True, maximum=4 * 1024 * 1024)
        for name in sorted(names)
    }


def _configuration(config, provider):
    _fields(config, CONFIG_FIELDS)
    if config["schema"] != CONFIG:
        raise ValueError("Unsupported coding session configuration")
    if (
        not isinstance(config["revision"], str)
        or not config["revision"]
        or len(config["revision"].encode()) > 1024
        or "\0" in config["revision"]
    ):
        raise ValueError("An explicit bounded source revision is required")
    for name in ("worker_image", "execution_image", "helper_image"):
        if (
            not isinstance(config[name], str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", config[name]) is None
        ):
            raise ValueError("Coding sessions require immutable local image IDs")
    for name, low, high in [
        ("command_timeout_seconds", 1, 300),
        ("timeout_seconds", 1, 3600),
        ("max_attempts", 1, 16),
        ("max_calls", 1, 1024),
        ("capability_ttl_seconds", 1, 86400),
    ]:
        _integer(config[name], low, high)
    request_budget = max(config["command_timeout_seconds"] + 120, provider["timeout_seconds"] + 30)
    if config["timeout_seconds"] < request_budget + 30:
        raise ValueError("Native attempt timeout must cover tool requests plus 30 seconds")
    agent = config["agent"]
    if not isinstance(agent, dict):
        raise ValueError("An explicit coding agent configuration is required")
    wall = agent.get("wall_time_limit_seconds")
    _integer(wall, 1, 86400)
    if wall < config["timeout_seconds"]:
        raise ValueError("Agent wall time must cover the native attempt timeout")
    if config["capability_ttl_seconds"] < max(
        wall, config["max_attempts"] * config["timeout_seconds"] + 60
    ):
        raise ValueError("Capability lifetime must cover the bounded task and restart attempts")


def initialize(config_path, task_path, state):
    from chio_mini_swe.gateway import tool as model_tool
    from chio_mini_swe.repository import tool as repository_tool
    from chio_mini_swe.repository_container import qualify_image
    from chio_mini_swe.repository_store import initialize as initialize_repository
    from chio_mini_swe.worker import validate_bootstrap

    path = Path(config_path).resolve(strict=True)
    config = session_security.read_document(path)
    _fields(config, CONFIG_FIELDS)
    provider_path = _path(path.parent, config["provider_config"])
    provider = validate(session_security.read_document(provider_path, maximum=65536))
    _configuration(config, provider)
    binary = _path(path.parent, config["chio"])
    operator.protected_executable(binary)
    binary_hash = operator.digest_file(binary)
    if not operator.supports_state_reader(binary):
        raise ValueError("The selected Chio binary lacks administrative process state reads")
    repository = _path(path.parent, config["repository"])
    environment = session_security.environment_identity()
    qualify_image(config["worker_image"])
    task = session_security.read_file(task_path, 128 * 1024).decode("utf-8")
    model_id = identity(provider)
    validate_bootstrap(
        {
            "schema": "chio.process.worker-bootstrap.v1",
            "input": {
                "schema": "chio.mini-swe.worker.v1",
                "run_id": "session-configuration-validation",
                "task": task,
                "model": {**ROUTES[0], "model_id": model_id},
                "environment": {**ROUTES[1], "template_vars": {"cwd": "/workspace"}},
                "agent": config["agent"],
            },
            "connection": {"protocol": "chio.process.v1", "tools": ROUTES},
        }
    )
    state = operator.private_directory(state, create=True)
    with session_security.exclusive_lock(state / "session.lock", create=True):
        # Inputs are captured before emitting commands whose signed arguments
        # refer to these exact paths. No provider credential is read or copied.
        atomic_bytes(state / "task.md", task.encode())
        operator.write(state / "provider.json", provider)
        workspace = initialize_repository(
            repository,
            config["revision"],
            config["execution_image"],
            config["helper_image"],
            state / "repository",
            config["command_timeout_seconds"],
        )
        configuration = dict(
            config,
            chio=str(binary),
            repository=str(repository),
            revision=workspace["source_commit"],
            provider_config=str(state / "provider.json"),
        )
        operator.write(state / "configuration.json", configuration)
        workspace_config = {key: value for key, value in workspace.items() if key != "state"}
        launchers = environment["launchers"]
        servers = {}
        for server, executable, arguments, tools, timeout in [
            (
                "model",
                "chio-mini-swe-model",
                ["--config", str(state / "provider.json")],
                [model_tool(model_id)],
                provider["timeout_seconds"] + 30,
            ),
            (
                "sandbox",
                "chio-mini-swe-repository",
                ["serve", "--state", str(state / "repository")],
                [repository_tool(workspace_config)],
                config["command_timeout_seconds"] + 120,
            ),
        ]:
            servers[server] = {
                "id": server,
                "command": [launchers[executable]["path"], *arguments],
                "working_directory": str(state),
                "execution_uid": os.getuid(),
                "execution_gid": os.getgid(),
                "tools": tools,
                "request_timeout_seconds": timeout,
            }
        request = {
            "schema": REQUEST,
            "state": str(state),
            "chio": str(binary),
            "binary_sha256": binary_hash,
            "source_commit": workspace["source_commit"],
            "workspace_id": workspace["id"],
            "configuration_sha256": configuration_digest(workspace_config),
            "model_id": model_id,
            "environment": environment,
            "servers": servers,
        }
        operator.write(state / "provisioning-request.json", request)
        record = {
            "schema": INITIALIZED,
            "state": str(state),
            "binary_sha256": binary_hash,
            "configuration_sha256": request["configuration_sha256"],
            "model_id": model_id,
            "environment": environment,
            "files": _hashes(state, INITIAL_FILES),
        }
        if (
            operator.digest_file(binary) != binary_hash
            or session_security.environment_identity() != environment
        ):
            raise ValueError("Chio or the installed package changed during initialization")
        operator.write(state / "initialized.json", record)
    return {
        "schema": INITIALIZED,
        "state": str(state),
        "source_commit": workspace["source_commit"],
        "model_id": model_id,
        "provisioning_request": str(state / "provisioning-request.json"),
    }


def _initialized(state, *, online=False):
    state = operator.private_directory(state)
    record = session_security.read_document(state / "initialized.json", private=True)
    _fields(
        record,
        {
            "schema",
            "state",
            "binary_sha256",
            "configuration_sha256",
            "model_id",
            "environment",
            "files",
        },
    )
    if record["schema"] != INITIALIZED or record["state"] != str(state):
        raise ValueError("Coding session is incomplete or has moved")
    _fields(record["files"], INITIAL_FILES)
    names = INITIAL_FILES if online else INITIAL_FILES - {"provider.json"}
    if _hashes(state, names) != {name: record["files"][name] for name in sorted(names)}:
        raise ValueError("Initialized coding session files changed")
    config = session_security.read_document(state / "configuration.json", private=True)
    _fields(config, CONFIG_FIELDS)
    operator.protected_executable(config["chio"])
    if operator.digest_file(config["chio"]) != record["binary_sha256"]:
        raise ValueError("The session Chio binary changed")
    if session_security.environment_identity() != record["environment"]:
        raise ValueError("The installed Chio Python sources or environment changed")
    workspace = session_security.read_document(
        state / "repository" / "workspace.json", private=True
    )
    if configuration_digest(workspace) != record["configuration_sha256"]:
        raise ValueError("The session repository configuration changed")
    if (
        online
        and identity(session_security.read_document(state / "provider.json", private=True))
        != record["model_id"]
    ):
        raise ValueError("The session provider configuration changed")
    return state, record, config


def _prepared(state, *, online=False):
    state, initialized, config = _initialized(state, online=online)
    record = session_security.read_document(state / "session-prepared.json", private=True)
    _fields(record, {"schema", "initialized_sha256", "files"})
    _fields(record["files"], PREPARED_FILES)
    if (
        record["schema"] != PREPARED
        or record["initialized_sha256"]
        != session_security.file_hash(state / "initialized.json", private=True)
        or _hashes(state, PREPARED_FILES) != record["files"]
    ):
        raise ValueError("Prepared coding session files changed")
    operator.prepared(state / "run", running=online)
    return state, initialized, config


def _policy(ttl):
    return (
        f"kernel:\n  max_capability_ttl: {ttl}\n  delegation_depth_limit: 1\n"
        "  durable_admission_mode: all\ncapabilities:\n  default:\n    tools:\n"
        "      - server: model\n        tool: model_infer\n"
        f"        operations: [invoke, delegate]\n        ttl: {ttl}\n"
        "      - server: sandbox\n        tool: execute\n"
        f"        operations: [invoke, delegate]\n        ttl: {ttl}\n"
    ).encode()


@contextlib.contextmanager
def _working_directory(state):
    previous = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.chdir(state)
        yield
    finally:
        os.fchdir(previous)
        os.close(previous)


def _policy_matches(data, requested):
    policy = session_security.document(data)
    try:
        runtime = policy["body"]["runtime"]
        matches = (
            runtime["target_path"] == requested["command"][0]
            and runtime["target_argv"] == requested["command"]
            and runtime["working_directory"] == requested["working_directory"]
            and runtime["execution_identity"]["uid"] == requested["execution_uid"]
            and runtime["execution_identity"]["gid"] == requested["execution_gid"]
        )
    except (KeyError, TypeError) as error:
        raise ValueError("Signed launch policy lacks the requested runtime bindings") from error
    if not matches:
        raise ValueError("Signed launch policy differs from the session provisioning request")


def prepare(state, authorization_path):
    state = operator.private_directory(state)
    with session_security.exclusive_lock(state / "session.lock"):
        state, _, config = _initialized(state, online=True)
        if any(
            os.path.lexists(state / name)
            for name in [*PREPARED_FILES, "run", "session-prepared.json"]
        ):
            raise ValueError(
                "Session preparation already started; preserve it and use a fresh session"
            )
        authorization_path = Path(authorization_path).resolve(strict=True)
        authorization = session_security.read_document(authorization_path)
        _fields(authorization, {"schema", "servers"})
        _fields(authorization["servers"], {"model", "sandbox"})
        if authorization["schema"] != AUTHORIZATION:
            raise ValueError("Unsupported session authorization document")
        request = session_security.read_document(state / "provisioning-request.json", private=True)
        policies, servers, pinned = {}, [], {}
        for name in ("model", "sandbox"):
            supplied = authorization["servers"][name]
            _fields(supplied, {"launch_policy", "launch_policy_signer"})
            signer = supplied["launch_policy_signer"]
            if not isinstance(signer, str) or re.fullmatch(r"[0-9a-f]{64}", signer) is None:
                raise ValueError("Each launch policy needs an independently pinned signer key")
            path = _path(authorization_path.parent, supplied["launch_policy"])
            policies[name] = session_security.read_file(path, 4 * 1024 * 1024)
            if not policies[name]:
                raise ValueError("Empty signed launch policy")
            _policy_matches(policies[name], request["servers"][name])
            policy = str(state / f"{name}-launch-policy.json")
            pinned[name] = {"launch_policy": policy, "launch_policy_signer": signer}
            servers.append(
                {
                    "id": name,
                    "command": request["servers"][name]["command"],
                    "request_timeout_seconds": request["servers"][name]["request_timeout_seconds"],
                    **pinned[name],
                }
            )
        # Capture exact signed bytes, without changing or re-signing their
        # authority. Native launch validation remains the authorization gate.
        for name, data in policies.items():
            atomic_bytes(state / f"{name}-launch-policy.json", data)
        operator.write(state / "authorization.json", {"schema": AUTHORIZATION, "servers": pinned})
        atomic_bytes(state / "policy.yaml", _policy(config["capability_ttl_seconds"]))
        host = {
            "schema": "chio.process.host.v1",
            "policy": str(state / "policy.yaml"),
            "servers": servers,
            "limits": {"max_processes": 2, "max_depth": 1, "max_calls": config["max_calls"]},
            "children": [
                {"id": "coder", "parent": "root", "budget_share_bps": 10000, "tools": ROUTES}
            ],
        }
        profile = {
            "schema": operator.PROFILE,
            "chio": config["chio"],
            "host_config": str(state / "host.json"),
            "provider_config": str(state / "provider.json"),
            "process": "coder",
            "worker_image": config["worker_image"],
            "model_server": "model",
            "execution": ROUTES[1],
            "environment": {"cwd": "/workspace"},
            "agent": config["agent"],
            "max_attempts": config["max_attempts"],
            "timeout_seconds": config["timeout_seconds"],
        }
        operator.write(state / "host.json", host)
        operator.write(state / "operator.json", profile)
        with _working_directory(state):
            value = operator.prepare(state / "operator.json", state / "task.md", state / "run")
        _initialized(state, online=True)
        operator.write(
            state / "session-prepared.json",
            {
                "schema": PREPARED,
                "initialized_sha256": session_security.file_hash(
                    state / "initialized.json", private=True
                ),
                "files": _hashes(state, PREPARED_FILES),
            },
        )
        return {"schema": PREPARED, "state": str(state), "operator": value}


def run(state):
    state, _, config = _prepared(state, online=True)
    # exec leaves signal ownership, admission recovery and resource leases with
    # the native host. No session lock is inherited by it or its tool servers.
    with _working_directory(state):
        os.execv(
            config["chio"],
            [
                config["chio"],
                "process",
                "run",
                "--state",
                str(state / "run" / "host"),
                "--plan",
                str(state / "run" / "plan.json"),
            ],
        )


def inspect(state):
    state, record, config = _initialized(state)
    prepared = (state / "session-prepared.json").exists()
    if prepared:
        _prepared(state)
    value = {
        "schema": "chio.mini-swe.session-status.v1",
        "state": str(state),
        "phase": "prepared" if prepared else "initialized",
        "model_id": record["model_id"],
        "source_commit": config["revision"],
    }
    if not prepared and any(os.path.lexists(state / name) for name in [*PREPARED_FILES, "run"]):
        value["phase"] = "preparation_incomplete"
    if prepared:
        value["host"] = operator.command(
            config["chio"], "process", "status", "--state", state / "run" / "host"
        )
    try:
        with Workspace(state / "repository") as workspace:
            value["repository"] = workspace.status()
    except BlockingIOError:
        value["repository"] = {"busy": True}
    return value


def recover(state):
    state = operator.private_directory(state)
    with session_security.exclusive_lock(state / "session.lock"):
        state, _, _ = _initialized(state)
        if (state / "session-prepared.json").exists():
            _prepared(state)
        with session_security.stopped_host(state), Workspace(state / "repository") as workspace:
            workspace.recover()
            return {
                "schema": "chio.mini-swe.session-recovery.v1",
                "state": str(state),
                "repository": workspace.status(),
            }


def result(state, output):
    from chio_mini_swe.repository import export
    from chio_mini_swe.repository_proof import verify

    state = operator.private_directory(state)
    with session_security.exclusive_lock(state / "session.lock"):
        state, record, config = _prepared(state)
        with session_security.stopped_host(state), Workspace(state / "repository") as workspace:
            output = operator.private_directory(output, create=True)
            native = operator.result(state / "run", output / "operator")
            proof, receipts, key = verify(
                workspace,
                binary=config["chio"],
                receipts_path=output / "operator" / "receipts.ndjson",
                key_path=output / "operator" / "kernel.pub",
                server_id="sandbox",
            )
            repository = export(workspace, output / "repository")
            atomic_bytes(output / "repository" / "receipts.ndjson", receipts)
            atomic_bytes(output / "repository" / "kernel.pub", key)
            operator.write(output / "repository" / "receipt-binding.json", proof)
            repository["verified_transitions"] = len(proof["transitions"])
            value = {
                "schema": "chio.mini-swe.session-result.v1",
                "output": str(output),
                "source_commit": config["revision"],
                "model_id": record["model_id"],
                "operator": native,
                "repository": repository,
                "kernel_key_sha256": digest(key),
            }
            operator.write(output / "result.json", value)
            return value


def add_parser(commands):
    parser = commands.add_parser("session", help="Initialize, authorize and run a repository task")
    phases = parser.add_subparsers(dest="session_command", required=True)
    for name in ("init", "prepare", "run", "status", "recover", "result"):
        phase = phases.add_parser(name)
        phase.add_argument("--state", required=True)
        if name == "init":
            phase.add_argument("--config", required=True)
            phase.add_argument("--task-file", required=True)
        if name == "prepare":
            phase.add_argument("--authorization", required=True)
        if name == "result":
            phase.add_argument("--out", required=True)


def dispatch(args):
    if args.session_command == "init":
        return initialize(args.config, args.task_file, args.state)
    if args.session_command == "prepare":
        return prepare(args.state, args.authorization)
    if args.session_command == "result":
        return result(args.state, args.out)
    return {"run": run, "status": inspect, "recover": recover}[args.session_command](args.state)

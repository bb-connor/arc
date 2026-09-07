"""Prepare, run and export one native coding task using operator-provisioned tools."""

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import uuid
from pathlib import Path

from chio_mini_swe.provider_config import identity, read_json

PROFILE = "chio.mini-swe.operator.v1"
PREPARED = "chio.mini-swe.prepared.v1"


def protected_parent(path):
    for parent in [path, *path.parents]:
        metadata = parent.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("Operator paths must use existing directories without symlinks")
        writable = metadata.st_mode & 0o022
        shared_temporary = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
        if writable and not shared_temporary:
            raise ValueError("Operator path has a directory writable by other users")


def private_directory(path, *, create=False):
    path = Path(os.path.abspath(path))
    protected_parent(path.parent)
    if create:
        path.mkdir(mode=0o700)
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_mode & 0o077
        or metadata.st_uid != os.getuid()
    ):
        raise ValueError("Operator state must be private and owned by this user")
    return path


def digest_file(path):
    with open(path, "rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def protected_executable(path):
    path = Path(path)
    protected_parent(path.parent)
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o022
        or metadata.st_uid not in {0, os.getuid()}
        or not os.access(path, os.X_OK)
    ):
        raise ValueError("Chio must be an executable protected from other users' writes")


def supports_state_reader(binary):
    result = subprocess.run(
        [str(binary), "process", "state", "--help"], capture_output=True, timeout=30
    )
    return result.returncode == 0


def write(path, value):
    data = json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2).encode() + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def command(binary, *arguments, diagnostic=None):
    result = subprocess.run(
        [str(binary), *(str(v) for v in arguments)], capture_output=True, timeout=180
    )
    if result.returncode:
        if diagnostic is not None:
            write(
                diagnostic,
                {
                    "exit_code": result.returncode,
                    "stderr": result.stderr[:65536].decode("utf-8", errors="replace"),
                },
            )
        raise RuntimeError("Chio command failed; inspect the retained native host state")
    if len(result.stdout) > 2 * 1024 * 1024:
        raise RuntimeError("Chio result exceeds its byte limit")
    return json.loads(result.stdout)


def prepare(profile_path, task_path, state):
    profile_path = Path(profile_path).resolve(strict=True)
    profile = read_json(profile_path, 1024 * 1024)
    fields = {
        "schema",
        "chio",
        "host_config",
        "provider_config",
        "process",
        "worker_image",
        "model_server",
        "execution",
        "environment",
        "agent",
        "max_attempts",
        "timeout_seconds",
    }
    if not isinstance(profile, dict) or set(profile) != fields or profile["schema"] != PROFILE:
        raise ValueError("Invalid native coding operator profile")
    paths = {}
    for key in ("chio", "host_config", "provider_config"):
        if not isinstance(profile[key], str):
            raise ValueError("Profile paths must be strings")
        paths[key] = (profile_path.parent / profile[key]).resolve(strict=True)
    protected_executable(paths["chio"])
    binary_hash = digest_file(paths["chio"])
    if not supports_state_reader(paths["chio"]):
        raise ValueError("This Chio binary does not support administrative process state reads")
    if (
        not isinstance(profile["worker_image"], str)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", profile["worker_image"]) is None
    ):
        raise ValueError("An immutable installed worker image is required")
    for key, maximum in [("max_attempts", 16), ("timeout_seconds", 3600)]:
        if type(profile[key]) is not int or not 1 <= profile[key] <= maximum:
            raise ValueError("Native attempt and timeout limits must be bounded integers")
    route = profile["execution"]
    if not isinstance(route, dict) or set(route) != {"server_id", "tool_name"}:
        raise ValueError("An explicit execution tool route is required")
    host = read_json(paths["host_config"], 1024 * 1024)
    if not isinstance(host, dict) or host.get("schema") != "chio.process.host.v1":
        raise ValueError("A provisioned native host configuration is required")
    base = paths["host_config"].parent
    host["policy"] = str((base / host["policy"]).resolve(strict=True))
    for server in host.get("servers", []):
        if not server.get("launch_policy") or not server.get("launch_policy_signer"):
            raise ValueError("Every tool server requires an explicit signed launch policy")
        server["launch_policy"] = str((base / server["launch_policy"]).resolve(strict=True))
    child = next(
        (child for child in host.get("children", []) if child.get("id") == profile["process"]), None
    )
    model_route = {"server_id": profile["model_server"], "tool_name": "model_infer"}
    if child is None or model_route not in child["tools"] or route not in child["tools"]:
        raise ValueError("The selected child needs the model and execution routes")
    with open(task_path, "rb") as stream:
        task = stream.read(128 * 1024 + 1).decode("utf-8")
    model_id = identity(read_json(paths["provider_config"]))
    data = {
        "schema": "chio.mini-swe.worker.v1",
        "run_id": uuid.uuid4().hex,
        "task": task,
        "model": {**model_route, "model_id": model_id},
        "environment": {**route, "template_vars": profile["environment"]},
        "agent": profile["agent"],
    }
    from chio_mini_swe.worker import validate_bootstrap

    validate_bootstrap(
        {
            "schema": "chio.process.worker-bootstrap.v1",
            "input": data,
            "connection": {
                "protocol": "chio.process.v1",
                "socket_path": "/unused",
                "credential": "validation-only",
                "tools": child["tools"],
            },
        }
    )
    state = private_directory(state, create=True)
    plan = {
        "schema": "chio.process.run.v1",
        "max_parallel": 1,
        "workers": [
            {
                "process": profile["process"],
                "command": ["/usr/local/bin/chio-mini-swe-worker"],
                "cwd": "/work",
                "container": {"image": profile["worker_image"]},
                "input": data,
                "max_attempts": profile["max_attempts"],
                "timeout_seconds": profile["timeout_seconds"],
            }
        ],
    }
    write(state / "host-config.json", host)
    write(state / "plan.json", plan)
    initialized = command(
        paths["chio"],
        "process",
        "init",
        "--config",
        state / "host-config.json",
        "--state",
        state / "host",
        diagnostic=state / "initialization-error.json",
    )
    prepared = {
        "schema": PREPARED,
        "chio": str(paths["chio"]),
        "binary_sha256": binary_hash,
        "process": profile["process"],
        "provider_config": str(paths["provider_config"]),
        "model_id": model_id,
        "kernel_key": initialized["kernel_key"],
        "files": {name: digest_file(state / name) for name in ("host-config.json", "plan.json")},
    }
    if digest_file(paths["chio"]) != binary_hash:
        raise RuntimeError("Chio changed during task initialization")
    # This final durable marker distinguishes a ready run from partial initialization.
    write(state / "prepared.json", prepared)
    return {"state": str(state), "model_id": model_id, "process": profile["process"]}


def prepared(state, *, running=False):
    state = private_directory(state)
    record = read_json(state / "prepared.json")
    if (
        not isinstance(record, dict)
        or set(record)
        != {
            "schema",
            "chio",
            "binary_sha256",
            "process",
            "provider_config",
            "model_id",
            "kernel_key",
            "files",
        }
        or not isinstance(record["files"], dict)
        or set(record["files"]) != {"host-config.json", "plan.json"}
    ):
        raise ValueError("Invalid prepared run record")
    protected_executable(record["chio"])
    if record.get("schema") != PREPARED or digest_file(record["chio"]) != record["binary_sha256"]:
        raise ValueError("Prepared run or Chio executable changed")
    for name, expected in record["files"].items():
        if name not in {"host-config.json", "plan.json"} or digest_file(state / name) != expected:
            raise ValueError("Prepared native run files changed")
    if running and identity(read_json(record["provider_config"])) != record["model_id"]:
        raise ValueError(
            "Provider configuration changed; the existing task cannot be reinterpreted"
        )
    return state, record


class AdministrativeState:
    """Only the CLI's filesystem-authorized read API, without any worker credential."""

    def __init__(self, state, record):
        self.state, self.record = state, record

    def read(self, *arguments):
        value = command(
            self.record["chio"],
            "process",
            "state",
            "--state",
            self.state / "host",
            "--process",
            self.record["process"],
            *arguments,
        )
        if (
            value.get("schema") != "chio.process.application-state.v1"
            or value.get("process") != self.record["process"]
        ):
            raise RuntimeError("Invalid native application state response")
        return value["data"]

    def inspect(self):
        return self.read()

    def read_blob(self, sha256):
        value = self.read("--blob", sha256)
        data = base64.b64decode(value["data_base64"], validate=True)
        if (
            len(data) > 1048576
            or len(data) != value["bytes"]
            or value["sha256"] != sha256
            or hashlib.sha256(data).hexdigest() != sha256
        ):
            raise RuntimeError("Invalid retained state blob")
        return data


def result(state, output):
    from chio_mini_swe.worker import export_result

    state, record = prepared(state)
    exported = export_result(AdministrativeState(state, record))
    output = private_directory(output, create=True)
    write(output / "result.json", exported)
    receipts = exported["model_receipts"] + exported["command_receipts"]
    for name, content in [
        ("kernel.pub", record["kernel_key"]),
        ("receipts.ndjson", "\n".join(receipts) + "\n"),
    ]:
        descriptor = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
    verified = command(
        record["chio"],
        "--json",
        "receipt",
        "verify",
        "--input",
        output / "receipts.ndjson",
        "--trusted-kernel-pubkey",
        output / "kernel.pub",
    )
    if verified["receipts_verified"] != len(receipts):
        raise RuntimeError("Receipt verification did not cover the exported trajectory")
    write(output / "verification.json", verified)
    submission = exported["result"].get("submission", "")
    return {
        "output": str(output),
        "exit_status": exported["result"].get("exit_status"),
        "submission_preview": submission[:1024],
        "submission_truncated": len(submission) > 1024,
        "model_calls": exported["model_calls"],
        "model_cost": exported["model_cost"],
        "verified_receipts": verified["receipts_verified"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Run a coding task on an operator-provisioned Chio host"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    setup = commands.add_parser("prepare")
    setup.add_argument("--profile", required=True)
    setup.add_argument("--task-file", required=True)
    setup.add_argument("--state", required=True)
    for name in ("run", "status", "result"):
        command_parser = commands.add_parser(name)
        command_parser.add_argument("--state", required=True)
        if name == "result":
            command_parser.add_argument("--out", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    if args.command in {"run", "status"}:
        state, record = prepared(args.state, running=args.command == "run")
        arguments = [record["chio"], "process", args.command, "--state", str(state / "host")]
        if args.command == "run":
            arguments += ["--plan", str(state / "plan.json")]
        # The native host becomes the foreground process and owns signals,
        # locks, reconciliation and exit status. No second supervisor is added.
        os.execv(record["chio"], arguments)
    with tempfile.TemporaryDirectory(prefix="chio-operator-") as private:
        os.environ["MSWEA_GLOBAL_CONFIG_DIR"] = private
        os.environ["MSWEA_SILENT_STARTUP"] = "1"
        if args.command == "prepare":
            value = prepare(args.profile, args.task_file, args.state)
        else:
            value = result(args.state, args.out)
        print(json.dumps(value, ensure_ascii=False, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

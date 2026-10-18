#!/usr/bin/python3
"""Docker reply double with exact-ID container state.

Scenario options apply globally and accept overrides in ``workers[tag]``. The
last worker command argument supplies the required tag. ``gates`` selects
create_before, create_after, confirm, or attachment.
Each gate writes ``containers/<sha256(owner)>/<phase>.ready`` with its PID and
waits at most 60 seconds for ``<phase>.release``. Gates are claimed once, so
concurrent inspection remains available. Removal retains evidence and deletes
only ``record.json``. Releasing attachment records an exited worker with the
configured ``worker_exit`` code, which defaults to zero.
"""

import fcntl
import hashlib
import json
import os
import re
import sys
import time
from contextlib import contextmanager
from pathlib import Path

root = Path(__file__).parent
scenario = json.loads((root / "scenario.json").read_text())
containers = root / "containers"
args = sys.argv[3:]
image = "sha256:" + "1" * 64


def settings(create):
    command = create[create.index("--entrypoint") + 3 :]
    if not command or not command[-1]:
        raise SystemExit("fixture worker tag is required")
    tag = command[-1]
    return {**scenario, **scenario.get("workers", {}).get(tag, {})}


def options(directory):
    return settings(json.loads((directory / "create_args.json").read_text()))


def exact_directory(identity):
    if re.fullmatch(r"[0-9a-f]{64}", identity) is None:
        raise SystemExit("refusing non-exact container ID")
    directory = containers / identity
    if not (directory / "record.json").exists():
        raise SystemExit(f"No such container: {identity}")
    return directory


@contextmanager
def locked(directory):
    with (directory / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield


def write_record(directory, record):
    temporary = directory / "record.tmp"
    temporary.write_text(json.dumps(record))
    temporary.replace(directory / "record.json")


def gate(directory, phase, selected):
    if phase not in selected.get("gates", []):
        return
    try:
        with (directory / f"{phase}.ready").open("x") as ready:
            ready.write(str(os.getpid()))
    except FileExistsError:
        return
    deadline = time.monotonic() + 60
    release = directory / f"{phase}.release"
    while not release.exists():
        if time.monotonic() >= deadline:
            raise SystemExit(f"fixture gate timed out: {directory.name}/{phase}")
        time.sleep(0.01)


def effective_config(directory, selected):
    """HostConfig as the engine reports the fixed create flags."""
    create = json.loads((directory / "create_args.json").read_text())
    user = create[create.index("--user") + 1]
    uid, gid = user.split(":")
    mount = dict(
        part.split("=", 1) if "=" in part else (part, True)
        for part in create[create.index("--mount") + 1].split(",")
    )
    host = {
        "Binds": None,
        "VolumesFrom": None,
        "CapAdd": None,
        "CapDrop": ["ALL"],
        "GroupAdd": None,
        "Devices": [],
        "SecurityOpt": ["no-new-privileges:true"],
        "Privileged": False,
        "ReadonlyRootfs": True,
        "NetworkMode": "none",
        "IpcMode": "private",
        "PidMode": "",
        "CgroupnsMode": "private",
        "UsernsMode": "",
        "UTSMode": "",
        "Memory": 536870912,
        "MemorySwap": 536870912,
        "NanoCpus": 1000000000,
        "PidsLimit": 64,
        "ShmSize": 8388608,
        "Ulimits": [
            {"Name": "nofile", "Hard": 128, "Soft": 128},
            {"Name": "core", "Hard": 0, "Soft": 0},
            {"Name": "fsize", "Hard": 16777216, "Soft": 16777216},
        ],
        "Tmpfs": {
            "/tmp": "rw,noexec,nosuid,nodev,size=16m,mode=1777",
            "/work": f"rw,noexec,nosuid,nodev,size=64m,uid={uid},gid={gid},mode=0700",
        },
        "Mounts": [
            {
                "Type": "bind",
                "Source": mount["src"],
                "Target": mount["dst"],
                "ReadOnly": mount.get("readonly") is True,
            }
        ],
        "Init": True,
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
        "LogConfig": {"Type": "none", "Config": {}},
        "Runtime": "runc",
    }
    host.update(selected.get("config_drift", {}))
    if (directory / "starts").exists():
        host.update(selected.get("config_drift_after_start", {}))
    return {
        "image": create[create.index("--entrypoint") + 2],
        "user": user,
        "volumes": None,
        "host": host,
    }


def matches(record, expression):
    key, value = expression.split("=", 1)
    if key == "name":
        return re.fullmatch(value, record["name"]) is not None
    if key == "id":
        return record["id"] == value
    if key == "label":
        label, separator, expected = value.partition("=")
        return label in record["labels"] and (
            not separator or record["labels"][label] == expected
        )
    raise SystemExit(f"unsupported inventory filter: {expression}")


if args[0] == "info":
    print(
        json.dumps(
            {
                "ID": "test-engine",
                "SecurityOptions": ["name=seccomp,profile=builtin"],
                "MemoryLimit": True,
                "SwapLimit": True,
                "CpuCfsQuota": True,
                "PidsLimit": True,
                "CgroupVersion": "2",
            }
        )
    )
elif args[:2] == ["image", "inspect"]:
    print(json.dumps({"Id": image, "Config": {"Volumes": None}}))
elif args[0] == "create":
    selected = settings(args)
    owner = args[args.index("--label") + 1].split("=", 1)[1]
    identity = hashlib.sha256(owner.encode()).hexdigest()
    directory = containers / identity
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "create_args.json").write_text(json.dumps(args))
    if selected.get("create") == "rejected":
        print(f"Error response from daemon: No such image: {image}", file=sys.stderr)
        raise SystemExit(1)
    if selected.get("create") == "response_lost":
        print("error during connect: unexpected EOF", file=sys.stderr)
        raise SystemExit(1)
    if selected.get("create") == "unconfirmed":
        print("x" * 100_000)
        raise SystemExit(0)
    gate(directory, "create_before", selected)
    with locked(directory):
        write_record(
            directory,
            {
                "id": identity,
                "name": "/" + args[args.index("--name") + 1],
                "labels": {"chio.runner.owner": owner},
                "running": False,
                "status": "created",
                "started_at": "0001-01-01T00:00:00Z",
                "exit_code": 0,
                "oom_killed": False,
            },
        )
    gate(directory, "create_after", selected)
    print(identity)
elif args[0] == "start":
    directory = exact_directory(args[-1])
    selected = options(directory)
    stored = directory / "record.json"
    with locked(directory):
        record = json.loads(stored.read_text())
        starts = directory / "starts"
        starts.write_text(str(int(starts.read_text()) + 1 if starts.exists() else 1))
        record.update(status="running", running=True, started_at="2026-01-01T00:00:00Z")
        if selected.get("exit_before_bootstrap"):
            record.update(status="exited", running=False, exit_code=1)
        write_record(directory, record)
    if selected.get("exit_before_bootstrap"):
        raise SystemExit(1)
    bootstrap = json.load(sys.stdin)
    temporary = directory / "bootstrap.tmp"
    temporary.write_text(json.dumps(bootstrap))
    temporary.replace(directory / "bootstrapped")
    gate(directory, "attachment", selected)
    with locked(directory):
        if not stored.exists():
            raise SystemExit("container removed during attachment")
        record = json.loads(stored.read_text())
        worker_status = (
            "exited"
            if "attachment" in selected.get("gates", [])
            else selected.get("worker_status", "exited")
        )
        record.update(
            status=worker_status,
            running=worker_status in ("running", "paused"),
            started_at="0001-01-01T00:00:00Z" if worker_status == "created" else "2026-01-01T00:00:00Z",
            oom_killed=selected.get("oom_killed", False),
            exit_code=selected.get("worker_exit", 0),
        )
        write_record(directory, record)
    print("x" * selected.get("start_output", 16))
    time.sleep(selected.get("start_sleep", 0))
    raise SystemExit(selected.get("attach_exit", 0))
elif args[:2] == ["container", "inspect"]:
    directory = exact_directory(args[-1])
    selected = options(directory)
    if selected.get("inspect_failure") and (directory / "starts").exists():
        raise SystemExit("engine inspection unavailable")
    record = json.loads((directory / "record.json").read_text())
    if record["running"]:
        gate(directory, "confirm", selected)
    if ".HostConfig" in args[3]:
        print(json.dumps(effective_config(directory, selected)))
        raise SystemExit(0)
    if selected.get("changed_identity") and (directory / "starts").exists():
        record["id"] = "b" * 64
    print(json.dumps(record))
elif args[:2] == ["container", "ls"]:
    filters = [args[index + 1] for index, arg in enumerate(args) if arg == "--filter"]
    for stored in sorted(containers.glob("*/record.json")):
        try:
            record = json.loads(stored.read_text())
        except FileNotFoundError:
            continue
        if all(matches(record, expression) for expression in filters):
            print(record["id"])
elif args[:2] == ["container", "rm"]:
    directory = exact_directory(args[-1])
    if options(directory).get("cleanup_failure"):
        raise SystemExit(1)
    with locked(directory):
        (directory / "record.json").unlink()
        (directory / "removed").write_text("1")
else:
    raise SystemExit(f"unexpected engine control: {args}")

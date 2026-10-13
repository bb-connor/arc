#!/usr/bin/python3
"""Docker reply double. The production runner owns all lifecycle decisions."""

import json
import sys
import time
from pathlib import Path

root = Path(__file__).parent
scenario = json.loads((root / "scenario.json").read_text())
stored = root / "container.json"
args = sys.argv[3:]
identity = "a" * 64
image = "sha256:" + "1" * 64
created = root / "create_args.json"


def effective_config():
    """HostConfig as the engine reports the fixed create flags."""
    create = json.loads(created.read_text())
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
    host.update(scenario.get("config_drift", {}))
    if (root / "starts").exists():
        host.update(scenario.get("config_drift_after_start", {}))
    return {
        "image": create[create.index("--entrypoint") + 2],
        "user": user,
        "volumes": None,
        "host": host,
    }


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
    if scenario.get("create") == "rejected":
        print(f"Error response from daemon: No such image: {image}", file=sys.stderr)
        raise SystemExit(1)
    if scenario.get("create") == "response_lost":
        print("error during connect: unexpected EOF", file=sys.stderr)
        raise SystemExit(1)
    if scenario.get("create") == "unconfirmed":
        print("x" * 100_000)
        raise SystemExit(0)
    owner = args[args.index("--label") + 1].split("=", 1)[1]
    created.write_text(json.dumps(args))
    stored.write_text(
        json.dumps(
            {
                "id": identity,
                "name": "/" + args[args.index("--name") + 1],
                "labels": {"chio.runner.owner": owner},
                "running": False,
                "status": "created",
                "started_at": "0001-01-01T00:00:00Z",
                "exit_code": 0,
                "oom_killed": False,
            }
        )
    )
    print(identity)
elif args[0] == "start":
    starts = root / "starts"
    starts.write_text(str(int(starts.read_text()) + 1 if starts.exists() else 1))
    record = json.loads(stored.read_text())
    record.update(status="running", running=True, started_at="2026-01-01T00:00:00Z")
    if scenario.get("exit_before_bootstrap"):
        record.update(status="exited", running=False, exit_code=1)
        stored.write_text(json.dumps(record))
        raise SystemExit(1)
    stored.write_text(json.dumps(record))
    json.load(sys.stdin)
    (root / "bootstrapped").write_text("1")
    worker_status = scenario.get("worker_status", "exited")
    record.update(
        status=worker_status,
        running=worker_status in ("running", "paused"),
        started_at="0001-01-01T00:00:00Z" if worker_status == "created" else "2026-01-01T00:00:00Z",
        oom_killed=scenario.get("oom_killed", False),
        exit_code=scenario.get("worker_exit", 0),
    )
    stored.write_text(json.dumps(record))
    print("x" * scenario.get("start_output", 16))
    time.sleep(scenario.get("start_sleep", 0))
    raise SystemExit(scenario.get("attach_exit", 0))
elif args[:2] == ["container", "inspect"]:
    if scenario.get("inspect_failure") and (root / "starts").exists():
        raise SystemExit("engine inspection unavailable")
    if ".HostConfig" in args[3]:
        print(json.dumps(effective_config()))
        raise SystemExit(0)
    record = json.loads(stored.read_text())
    if scenario.get("changed_identity") and (root / "starts").exists():
        record["id"] = "b" * 64
    print(json.dumps(record))
elif args[:2] == ["container", "ls"]:
    if stored.exists():
        print(identity)
elif args[:2] == ["container", "rm"]:
    if args[-1] != identity:
        raise SystemExit("refusing non-exact removal")
    if scenario.get("cleanup_failure"):
        raise SystemExit(1)
    stored.unlink()
else:
    raise SystemExit(f"unexpected engine control: {args}")

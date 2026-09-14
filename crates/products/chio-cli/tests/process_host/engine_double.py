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
    json.load(sys.stdin)
    starts = root / "starts"
    starts.write_text(str(int(starts.read_text()) + 1 if starts.exists() else 1))
    record = json.loads(stored.read_text())
    worker_status = scenario.get("worker_status", "exited")
    record.update(
        status=worker_status,
        running=worker_status == "running",
        started_at="0001-01-01T00:00:00Z" if worker_status == "created" else "2026-01-01T00:00:00Z",
    )
    stored.write_text(json.dumps(record))
    print("x" * scenario.get("start_output", 16))
    time.sleep(scenario.get("start_sleep", 0))
    raise SystemExit(scenario.get("attach_exit", 0))
elif args[:2] == ["container", "inspect"]:
    if scenario.get("inspect_failure") and (root / "starts").exists():
        raise SystemExit("engine inspection unavailable")
    print(stored.read_text())
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

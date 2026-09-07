"""Operator-selected authority templates and executable plans, with no review jobs."""

import hashlib
import sys

from snapshot import digest

from .common import HERE


def application_hash():
    files = [HERE / name for name in ("snapshot.py", "tools.py", "adaptive_review.py")]
    files += [
        HERE / "adaptive" / name
        for name in (
            "__init__.py",
            "cli.py",
            "common.py",
            "configuration.py",
            "graphs.py",
            "planning.py",
            "publisher.py",
            "verification.py",
            "worker.py",
        )
    ]
    return digest(
        {
            str(path.relative_to(HERE)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in files
        }
    )


def route(server, tool):
    return {"server_id": server, "tool_name": tool}


def host(config, directory):
    slots = range(1, config["max_reviews"] + 1)
    channels = ["plan"] + [f"review_{slot}" for slot in slots]
    reads = [route("repo", name) for name in ("changes", "read_file")]
    sends = [route("chio-ipc", "send_" + channel) for channel in channels]
    spawns = [route("chio-process", f"spawn_review_{slot}") for slot in slots]
    return {
        "schema": "chio.process.host.v1",
        "policy": "policy.yaml",
        "servers": [
            {
                "id": "repo",
                "command": [
                    sys.executable,
                    str(HERE / "tools.py"),
                    "--snapshot",
                    str(directory / "snapshot.json"),
                    "--snapshot-hash",
                    config["snapshot_hash"],
                    "--database",
                    str(directory / "publications.db"),
                ],
            }
        ],
        "mailboxes": [
            {
                "id": channel,
                "limits": {
                    "max_pending_messages": 1,
                    "max_messages": 1,
                    "max_pending_bytes": 65536,
                    "max_message_bytes": 65536,
                },
            }
            for channel in channels
        ],
        "limits": {
            "max_processes": config["max_reviews"] + 3,
            "max_depth": 2,
            "max_calls": config["max_calls"],
        },
        "children": [
            {
                "id": "coordinator",
                "parent": "root",
                "budget_share_bps": 8000,
                "tools": reads
                + sends
                + spawns
                + [route("chio-process", "wait_children")],
            },
            {
                "id": "publisher",
                "parent": "root",
                "budget_share_bps": 2000,
                "tools": [route("repo", "publish_report")]
                + [
                    route("chio-ipc", operation + "_" + channel)
                    for channel in channels
                    for operation in ("receive", "ack")
                ],
            },
        ],
        "spawn_templates": [
            {
                "id": f"review_{slot}",
                "max_budget_share_bps": 8000 // config["max_reviews"],
                "tools": reads + [route("chio-ipc", f"send_review_{slot}")],
            }
            for slot in slots
        ],
    }


def plan(config, directory):
    executable = [sys.executable, str(HERE / "adaptive_review.py"), "worker"]

    def settings(role, slot=None):
        return {**config, "directory": str(directory), "role": role, "slot": slot}

    return {
        "schema": "chio.process.run.v1",
        "max_parallel": config["max_parallel"],
        "workers": [
            {
                "process": role,
                "command": executable,
                "cwd": str(HERE),
                "input": settings(role),
                "depends_on": ["coordinator"] if role == "publisher" else [],
                "max_attempts": 4,
                "timeout_seconds": 600,
            }
            for role in ("coordinator", "publisher")
        ],
        "templates": [
            {
                "id": f"review_{slot}",
                "command": executable,
                "cwd": str(HERE),
                "input": settings("reviewer", slot),
                "max_attempts": 3,
                "timeout_seconds": 600,
            }
            for slot in range(1, config["max_reviews"] + 1)
        ],
    }


POLICY = """kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 4
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: repo
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
      - server: chio-process
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
"""

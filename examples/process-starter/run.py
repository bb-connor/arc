"""Install local SDK artifacts and run the example outside the Chio checkout."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

HERE = Path(__file__).resolve().parent


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def command(args, cwd, env):
    result = subprocess.run(
        [str(arg) for arg in args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if result.returncode:
        # Commands do not receive credentials in argv or environment.
        raise RuntimeError(f"{Path(str(args[0])).name} failed:\n{result.stderr}")
    return result.stdout


def prepare(state, pins, recovery, env):
    state.mkdir(mode=0o700)
    app = state / "app"
    app.mkdir(mode=0o700)
    for name in ("producer.py", "consumer.mjs"):
        shutil.copyfile(HERE / name, app / name)
    venv.EnvBuilder(with_pip=True).create(state / "venv")
    python = state / "venv/bin/python"
    wheel = next((HERE / "packages").glob("*.whl"))
    command(
        [
            python,
            "-I",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
            wheel,
        ],
        app,
        env,
    )
    write(app / "package.json", {"name": "chio-process-starter", "private": True})
    package = next((HERE / "packages").glob("*.tgz"))
    command(
        [
            "npm",
            "install",
            "--offline",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--package-lock=false",
            package,
        ],
        app,
        env,
    )
    (state / "policy.yaml").write_text(
        """kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 1
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""",
        encoding="utf-8",
    )
    write(
        state / "host.json",
        {
            "schema": "chio.process.host.v1",
            "policy": str(state / "policy.yaml"),
            "mailboxes": [{"id": "jobs"}],
            "limits": {"max_processes": 3, "max_depth": 1, "max_calls": 10},
            "children": [
                {
                    "id": role,
                    "parent": "root",
                    "budget_share_bps": 5000,
                    "tools": [{"server_id": "chio-ipc", "tool_name": name} for name in names],
                }
                for role, names in (
                    ("producer", ["send_jobs"]),
                    ("consumer", ["receive_jobs", "ack_jobs"]),
                )
            ],
        },
    )
    initialized = json.loads(
        command(
            [
                HERE / "bin/chio",
                "--json",
                "process",
                "init",
                "--state",
                state / "host",
                "--config",
                state / "host.json",
            ],
            state,
            env,
        )
    )
    (state / "kernel.pub").write_text(initialized["kernel_key"] + "\n", encoding="ascii")
    node = shutil.which("node")
    require(node is not None, "Node 22+ is required")
    write(
        state / "plan.json",
        {
            "schema": "chio.process.run.v1",
            "max_parallel": 2,
            "workers": [
                {
                    "process": role,
                    "command": executable,
                    "cwd": str(app),
                    "input": {"directory": str(app), "exercise_recovery": recovery},
                    "depends_on": [] if role == "producer" else ["producer"],
                    "max_attempts": 2,
                    "timeout_seconds": 30,
                }
                for role, executable in (
                    ("producer", [str(python), "-I", str(app / "producer.py")]),
                    ("consumer", [node, str(app / "consumer.mjs")]),
                )
            ],
        },
    )
    write(state / "run.json", {"files": pins, "exercise_recovery": recovery})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state", type=Path, required=True, help="new private state directory")
    parser.add_argument("--exercise-recovery", action="store_true")
    args = parser.parse_args()
    require(sys.platform == "linux", "the native worker runner requires Linux")
    os.umask(0o077)
    state = args.state.resolve()
    manifest = json.loads((HERE / "manifest.json").read_text())
    pins = manifest["files"]
    for name, expected in pins.items():
        path = HERE / name
        require(path.resolve().is_relative_to(HERE), "artifact path escapes starter")
        require(digest(path) == expected, f"artifact changed: {name}")
    # Isolated Python mode and a clean Node module environment prevent a
    # development checkout from accidentally satisfying package imports.
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("PYTHON") and key not in ("NODE_PATH", "NODE_OPTIONS")
    }
    if not state.exists():
        prepare(state, pins, args.exercise_recovery, env)
    else:
        require(
            (state / "run.json").is_file(), "partial initialization; use a fresh state directory"
        )
        expected = {"files": pins, "exercise_recovery": args.exercise_recovery}
        require(
            json.loads((state / "run.json").read_text()) == expected,
            "application artifacts or recovery mode changed; use fresh state",
        )
    report = json.loads(
        command(
            [
                HERE / "bin/chio",
                "process",
                "run",
                "--state",
                state / "host",
                "--plan",
                state / "plan.json",
            ],
            state,
            env,
        )
    )
    require(report["complete"], "workers did not complete")
    producers = [
        json.loads(path.read_text()) for path in sorted((state / "app").glob("producer-*.json"))
    ]
    require(bool(producers), "missing producer result")
    require(
        all(item["send_receipt"] == producers[0]["send_receipt"] for item in producers),
        "retry did not return the original send receipt",
    )
    consumer = json.loads((state / "app/consumer.json").read_text())
    receipts = [producers[0]["send_receipt"], producers[-1]["scope_receipt"]] + consumer["receipts"]
    require(len(set(receipts)) == 5, "expected five distinct signed decisions")
    (state / "receipts.ndjson").write_text("\n".join(receipts) + "\n", encoding="utf-8")
    verified = json.loads(
        command(
            [
                HERE / "bin/chio",
                "--json",
                "receipt",
                "verify",
                "--input",
                state / "receipts.ndjson",
                "--trusted-kernel-pubkey",
                state / "kernel.pub",
            ],
            state,
            env,
        )
    )
    evidence = {
        "schema": "chio.process.starter-result.v1",
        "result": consumer["result"],
        "runner": report,
        "verification": verified,
        "known_handoff_replayed": len(producers) > 1,
    }
    write(state / "result.json", evidence)
    print(json.dumps(evidence, indent=2))


if __name__ == "__main__":
    main()

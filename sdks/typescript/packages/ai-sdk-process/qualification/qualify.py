"""Qualify installed AI SDK 6/7 adapters against native Chio and a non-idempotent effect."""

import argparse
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import unquote, urlparse

HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
TYPESCRIPT = PACKAGE.parent.parent


def command(args, directory, *, success=True):
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in ("NODE_PATH", "NODE_OPTIONS") and not key.startswith("PYTHON")
    }
    result = subprocess.run(
        list(map(str, args)),
        cwd=directory,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    return result


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def count(directory):
    path = directory / "publications.db"
    if not path.exists():
        return 0
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as db:
        return db.execute("SELECT count(*) FROM reports").fetchone()[0]


def settings(directory, consumer, mode):
    directory.mkdir(mode=0o700)
    return {
        "directory": str(directory),
        "mode": mode,
        "streaming": mode in ("host-death", "denied"),
        "database": str(directory / "publications.db"),
        "python": sys.executable,
        "server": str(consumer / "server.py"),
    }


def prepare(binary, directory, consumer, mode):
    pressure = mode.startswith("pressure-")
    data = settings(directory, consumer, mode)
    (directory / "policy.yaml").write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 1
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: reports
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    server = [
        sys.executable,
        str(consumer / "server.py"),
        "--database",
        data["database"],
    ]
    if mode == "lost-output":
        server.append("--exit-after-publication")
    write(
        directory / "host-config.json",
        {
            "schema": "chio.process.host.v1",
            "policy": "policy.yaml",
            "servers": [{"id": "reports", "command": server}],
            "limits": {
                "max_processes": 2,
                "max_depth": 1,
                "max_calls": 40 if pressure else 10,
                **({"state": {"max_bytes": 1, "max_blobs": 1}} if mode == "pressure-quota" else {}),
            },
            "children": [
                {
                    "id": "writer",
                    "parent": "root",
                    "budget_share_bps": 10000,
                    "tools": [
                        {
                            "server_id": "reports",
                            "tool_name": "read" if pressure else "publish",
                        }
                    ],
                }
            ],
        },
    )
    initialized = json.loads(
        command(
            [
                binary,
                "process",
                "init",
                "--config",
                directory / "host-config.json",
                "--state",
                directory / "host",
            ],
            directory,
        ).stdout
    )
    (directory / "kernel.pub").write_text(initialized["kernel_key"] + "\n")
    write(
        directory / "worker-plan.json",
        {
            "schema": "chio.process.run.v1",
            "max_parallel": 1,
            "workers": [
                {
                    "process": "writer",
                    "command": [shutil.which("node"), str(consumer / "worker.mjs")],
                    "cwd": str(consumer),
                    "input": data,
                    "depends_on": [],
                    "max_attempts": 3,
                    "timeout_seconds": 90,
                }
            ],
        },
    )
    return [
        binary,
        "process",
        "run",
        "--state",
        directory / "host",
        "--plan",
        directory / "worker-plan.json",
    ]


def host_death(invoke, directory):
    oracle = directory / "first-result.json"
    with (directory / "host-crash.log").open("wb") as log:
        process = subprocess.Popen(list(map(str, invoke)), cwd=directory, stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 90
            while not oracle.exists():
                assert process.poll() is None, "host exited before known publication result"
                assert time.monotonic() < deadline, "known publication result did not arrive"
                time.sleep(0.05)
            first = json.loads(oracle.read_text())
            oracle.unlink()
            worker = json.loads((directory / "started-1.json").read_text())["pid"]
            process.kill()
            process.wait(timeout=10)
            deadline = time.monotonic() + 5
            while True:
                try:
                    if Path(f"/proc/{worker}/stat").read_text().split(") ", 1)[1][0] == "Z":
                        break
                except (FileNotFoundError, ProcessLookupError):
                    break
                assert time.monotonic() < deadline, "worker outlived its native host"
                time.sleep(0.05)
            return first
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


def verify(binary, directory, events):
    receipts = list(dict.fromkeys(event["result"]["receipt_json"] for event in events))
    assert receipts
    (directory / "receipts.ndjson").write_text("".join(receipt + "\n" for receipt in receipts))
    result = command(
        [
            binary,
            "--json",
            "receipt",
            "verify",
            "--input",
            directory / "receipts.ndjson",
            "--trusted-kernel-pubkey",
            directory / "kernel.pub",
        ],
        directory,
    )
    verified = json.loads(result.stdout)
    assert verified["receipts_verified"] == len(receipts)
    return verified


def installed_consumer(major, temporary, packages):
    consumer = temporary / major
    consumer.mkdir(mode=0o700)
    for name in ("package.json", "package-lock.json"):
        shutil.copyfile(HERE / major / name, consumer / name)
    cache = consumer / "npm-cache"
    command(
        ["npm", "ci", "--cache", cache, "--ignore-scripts", "--no-audit", "--no-fund"],
        consumer,
    )
    # Resolve the two local packages into a complete consumer lock before
    # offline installation. npm ci alone caches tarballs, not peer metadata.
    locked = json.loads((consumer / "package-lock.json").read_text())["packages"]
    command(
        [
            "npm",
            "install",
            "--cache",
            cache,
            "--package-lock-only",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            *packages,
        ],
        consumer,
    )
    resolved = json.loads((consumer / "package-lock.json").read_text())["packages"]
    for name, package in locked.items():
        if name:
            for field in ("version", "resolved", "integrity"):
                assert resolved[name].get(field) == package.get(field), (name, field)
    command(
        [
            "npm",
            "ci",
            "--cache",
            cache,
            "--offline",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
        ],
        consumer,
    )
    for name in (
        "worker.mjs",
        "server.py",
        "typecheck.ts",
        "journal_worker.mjs",
        "model_server.py",
        "pressure_worker.mjs",
    ):
        shutil.copyfile(HERE / name, consumer / name)
    command(
        [
            consumer / "node_modules/.bin/tsc",
            "--noEmit",
            "--strict",
            "--skipLibCheck",
            "--target",
            "ES2022",
            "--module",
            "Node16",
            "--moduleResolution",
            "Node16",
            "typecheck.ts",
        ],
        consumer,
    )
    return consumer


def exercise(binary, output, temporary, packages, inputs):
    summary = {}
    for major in ("ai6", "ai7"):
        consumer = installed_consumer(major, temporary, packages)
        destination = output / major
        destination.mkdir()
        shutil.copyfile(consumer / "package-lock.json", destination / "consumer-lock.json")
        baseline = temporary / f"{major}-baseline"
        write(baseline / "settings.json", settings(baseline, consumer, "baseline"))
        baseline_command = [
            "node",
            consumer / "worker.mjs",
            "--baseline",
            baseline / "settings.json",
        ]
        first = command([*baseline_command, "1"], consumer, success=False)
        assert first.returncode == 77 and count(baseline) == 1
        plan = (baseline / "model-plan.json").read_bytes()
        (baseline / "first-result.json").unlink()
        command([*baseline_command, "2"], consumer)
        assert count(baseline) == 2 and (baseline / "model-plan.json").read_bytes() == plan
        profiles = {"unmediated-callback": {"publications": 2, "completed": True}}
        shutil.copyfile(baseline / "result.json", destination / "baseline.json")
        for mode in ("worker-death", "host-death", "denied", "lost-output", "conflict"):
            directory = temporary / f"{major}-{mode}"
            invoke = prepare(binary, directory, consumer, mode)
            first = host_death(invoke, directory) if mode == "host-death" else None
            success = mode in ("worker-death", "host-death")
            executed = command(invoke, directory, success=success)
            oracle = directory / "first-result.json"
            if oracle.exists():
                first = json.loads(oracle.read_text())
                oracle.unlink()
            if success:
                runner = json.loads(executed.stdout)
                assert runner["complete"] and runner["workers"][0]["attempts"] == 2
                result = json.loads((directory / "result.json").read_text())
                events = result["receipts"]
                assert len(events) == 1 and first == events[0]
                assert result["model_calls"] == 2
                for url in result["modules"].values():
                    assert (
                        Path(unquote(urlparse(url).path))
                        .resolve()
                        .is_relative_to(consumer / "node_modules")
                    )
                original = (directory / "result.json").read_bytes()
                assert json.loads(command(invoke, directory).stdout) == runner
                assert (directory / "result.json").read_bytes() == original
            else:
                with sqlite3.connect(directory / "host/runner.db") as db:
                    assert db.execute(
                        "SELECT state,attempts FROM run_workers WHERE process='writer'"
                    ).fetchone() == ("failed", 3)
                result = json.loads((directory / "failure-3.json").read_text())
                assert result["model_calls"] == 1
                expected = "conflict" if mode == "conflict" else "kernel_denied"
                assert result["code"] == expected, result
                events = result["receipts"] if first is None else [first]
            assert count(directory) == (0 if mode == "denied" else 1)
            verified = verify(binary, directory, events)
            if mode == "denied":
                assert (
                    json.loads(events[0]["result"]["receipt_json"])["decision"]["verdict"] == "deny"
                )
            case = destination / mode
            case.mkdir()
            write(case / "result.json", result)
            for name in ("receipts.ndjson", "kernel.pub", "model-plan.json"):
                shutil.copyfile(directory / name, case / name)
            profiles[mode] = {
                "publications": count(directory),
                "completed": success,
                "receipts_verified": verified["receipts_verified"],
            }
            print(
                json.dumps({"sdk": major, "profile": mode, **profiles[mode]}),
                flush=True,
            )
        from journal_profiles import exercise_journal
        from pressure_profiles import exercise_pressure

        profiles["model-journal"] = exercise_journal(binary, destination, temporary, consumer)
        profiles["state-pressure"] = exercise_pressure(binary, destination, temporary, consumer)
        summary[major] = profiles
    write(
        output / "qualification.json",
        {
            "schema": "chio.ai-sdk.process-qualification.v1",
            "inputs": inputs,
            "profiles": summary,
            "live_model_called": False,
        },
    )


def main():
    if not __debug__:
        raise SystemExit("run qualification without Python optimization")
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700, exist_ok=False)
    package_dir = output / "packages"
    package_dir.mkdir()
    command(
        ["npm", "run", "build", "--workspace", "@chio-protocol/ai-sdk-process"],
        TYPESCRIPT,
    )
    packages = []
    for source in (TYPESCRIPT / "packages/process", PACKAGE):
        packed = json.loads(
            command(["npm", "pack", "--pack-destination", package_dir, "--json"], source).stdout
        )
        packages.append(package_dir / packed[0]["filename"])
    temporary = Path(tempfile.mkdtemp(prefix="chio-aip-"))
    binary = args.chio.resolve(strict=True)
    inputs = {
        "qualification_checkout": {
            "commit": command(["git", "rev-parse", "HEAD"], PACKAGE).stdout.strip(),
            "dirty": bool(command(["git", "status", "--porcelain"], PACKAGE).stdout),
        },
        "platform": {"system": platform.system(), "machine": platform.machine()},
        "node": command(["node", "--version"], PACKAGE).stdout.strip(),
        "npm": command(["npm", "--version"], PACKAGE).stdout.strip(),
        "python": platform.python_version(),
        "sha256": {},
    }
    for path in [binary, *packages]:
        with path.open("rb") as stream:
            inputs["sha256"][path.name] = hashlib.file_digest(stream, "sha256").hexdigest()
    try:
        exercise(binary, output, temporary, packages, inputs)
    except BaseException:
        print(f"Preserved private failure state: {temporary}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    main()

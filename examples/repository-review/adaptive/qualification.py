"""Native application qualification helpers; never imported by a worker."""

import json
import os
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from qualify import command

from . import configuration
from .common import HERE, persist


def commits(directory):
    repo = directory / "repo"
    repo.mkdir()
    command("git", "init", "-q", repo)

    def commit(message):
        command("git", "-C", repo, "add", ".")
        command(
            "git",
            "-C",
            repo,
            "-c",
            "user.name=Review Test",
            "-c",
            "user.email=review@example.invalid",
            "commit",
            "--no-verify",
            "-qm",
            message,
        )
        return command("git", "-C", repo, "rev-parse", "HEAD").stdout.strip()

    for name in ("api/main.py", "api/test_main.py", "web/index.py"):
        path = repo / name
        path.parent.mkdir(exist_ok=True)
        path.write_text("value = 1\n")
    base = commit("base")
    for path in repo.rglob("*.py"):
        path.write_text("value = 2\n")
    head = commit("head")
    (repo / "worker").mkdir()
    (repo / "worker/runner.py").write_text("value = 3\n")
    expanded = commit("expanded")
    return repo, base, head, expanded


def prepare(binary, directory, repo, base, head, profile="inventory", **settings):
    command(
        sys.executable,
        HERE / "adaptive_review.py",
        "prepare",
        "--repo",
        repo,
        "--base",
        base,
        "--head",
        head,
        "--run-dir",
        directory,
        "--chio",
        binary,
        "--model-factory",
        profile,
        "--max-parallel",
        "1",
        "--max-reviews",
        "4",
    )
    config = json.loads((directory / "run.json").read_text())
    # Faults and round ceilings are test inputs pinned before the first run.
    config.update(settings)
    persist(directory / "run.json", config)
    plan = configuration.plan(config, directory)
    persist(directory / "worker-plan.json", plan)
    assert {worker["process"] for worker in plan["workers"]} == {
        "coordinator",
        "publisher",
    }
    with sqlite3.connect(directory / "host/process.db") as db:
        assert db.execute("SELECT count(*) FROM process_child_work").fetchone()[0] == 0
    return config


def run(directory, *, success=True, env=None):
    return command(
        sys.executable,
        HERE / "adaptive_review.py",
        "run",
        "--run-dir",
        directory,
        success=success,
        env=env,
    )


def evidence(directory, count):
    result = json.loads((directory / "evidence.json").read_text())
    assert result["runner"]["complete"] and result["publications"] == 1
    assert len(result["reviews"]) == count and len(result["children"]) == count
    assert len(result["runner"]["workers"]) == count + 2
    assert (
        len({worker["worker_pid"] for worker in result["workers"].values()})
        == count + 2
    )
    snapshot = json.loads((directory / "snapshot.json").read_text())
    assert {path for review in result["reviews"] for path in review["paths"]} == {
        file["path"] for file in snapshot["files"]
    }
    with sqlite3.connect(directory / "host/process.db") as db:
        children = db.execute(
            "SELECT process_id,parent_id,template,input FROM process_child_work"
        ).fetchall()
    assert len(children) == count
    for process, parent, template, data in children:
        slot = result["workers"][process]["slot"]
        assert parent == "coordinator" and template == f"review_{slot}"
        assert json.loads(data) == result["reviews"][slot - 1]
    with sqlite3.connect(directory / "host/mailboxes.db") as db:
        used = db.execute(
            "SELECT id,last_sequence,acknowledged_through FROM mailboxes WHERE last_sequence > 0"
        ).fetchall()
    assert sorted(used) == sorted(
        [("plan", 1, 1)] + [(f"review_{slot}", 1, 1) for slot in range(1, count + 1)]
    )
    return result


def first_receipts(directory):
    first = {}
    for path in (directory / "workers").glob("*/first-*.json"):
        first[path.parent.name] = json.loads(path.read_text())
        path.unlink()
    return first


def same_receipts(first, result):
    for process, receipts in first.items():
        assert all(
            receipt in result["workers"][process]["receipts"] for receipt in receipts
        )


def crash_host(config, directory, env):
    oracle = directory / "workers/coordinator/first-spawn.json"
    with (directory / "crash-host.log").open("wb") as log:
        process = subprocess.Popen(
            [
                config["chio"],
                "process",
                "run",
                "--state",
                str(directory / "host"),
                "--plan",
                str(directory / "worker-plan.json"),
            ],
            stdout=log,
            stderr=log,
            env=env,
        )
        try:
            deadline = time.monotonic() + 90
            while not oracle.exists():
                assert process.poll() is None, (
                    "host exited before the known spawn result"
                )
                assert time.monotonic() < deadline, "known spawn result did not arrive"
                time.sleep(0.05)
            first = first_receipts(directory)
            worker = json.loads(
                (directory / "workers/coordinator/started-1.json").read_text()
            )["pid"]
            process.kill()
            process.wait(timeout=10)
            deadline = time.monotonic() + 5
            while True:
                try:
                    state = (
                        Path(f"/proc/{worker}/stat").read_text().split(") ", 1)[1][0]
                    )
                    if state == "Z":
                        break
                except (FileNotFoundError, ProcessLookupError):
                    break
                assert time.monotonic() < deadline, "worker outlived its host"
                time.sleep(0.05)
            return first
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


def no_publication(directory):
    database = directory / "publications.db"
    if database.exists():
        with sqlite3.connect(database) as db:
            assert db.execute("SELECT count(*) FROM reports").fetchone()[0] == 0


def export(directory, output, name, result):
    destination = output / name
    destination.mkdir(mode=0o700)
    for filename in ("report.md", "evidence.json", "receipts.ndjson", "kernel.pub"):
        (destination / filename).write_bytes((directory / filename).read_bytes())
    return {
        "reviews": len(result["reviews"]),
        "publications": result["publications"],
        "receipts_verified": result["receipt_verification"]["receipts_verified"],
        "attempts": {
            worker["process"]: worker["attempts"]
            for worker in result["runner"]["workers"]
        },
    }


def model_env(directory):
    return {
        **os.environ,
        "CHIO_ADAPTIVE_MODEL_TRACE": str(directory / "model-trace.ndjson"),
    }


def model_trace(directory):
    return [
        json.loads(line)
        for line in (directory / "model-trace.ndjson").read_text().splitlines()
    ]

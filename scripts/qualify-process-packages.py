#!/usr/bin/env python3
"""Build an offline starter and qualify installed process SDKs with a native host."""

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
import venv
import zipfile
from pathlib import Path
from urllib.parse import unquote, urlparse

ROOT = Path(__file__).resolve().parents[1]


def command(args, cwd, env, *, success=True):
    result = subprocess.run(
        [str(arg) for arg in args],
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    return result.stdout


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def qualify(kit, work, env):
    state = work / "state"
    started = time.monotonic()
    invoke = [sys.executable, "-I", kit / "run.py", "--state", state, "--exercise-recovery"]
    evidence = json.loads(command(invoke, work, env))
    assert evidence["result"] == {"item_count": 3, "total": 10}
    assert evidence["verification"]["receipts_verified"] == 5
    assert evidence["known_handoff_replayed"] is True
    jobs = {job["process"]: job for job in evidence["runner"]["workers"]}
    assert jobs["producer"]["attempts"] == 2
    assert jobs["consumer"]["attempts"] == 1
    assert all(job["state"] == "completed" for job in jobs.values())
    observed = json.loads(
        command(
            [
                kit / "bin/chio",
                "process",
                "status",
                "--state",
                state / "host",
            ],
            work,
            env,
        )
    )
    assert observed["host_lock_held"] is False
    assert all(
        w["state"] == "completed" and not w["waiting_on"] for w in observed["run"]["workers"]
    )
    logs = json.loads(
        command(
            [
                kit / "bin/chio",
                "process",
                "logs",
                "--state",
                state / "host",
                "--process",
                "producer",
                "--attempt",
                "2",
            ],
            work,
            env,
        )
    )
    assert logs["schema"] == "chio.process.logs.v1"
    assert set(logs["logs"]) == {"stdout", "stderr"}
    producer = json.loads((state / "app/producer-2.json").read_text())
    consumer = json.loads((state / "app/consumer.json").read_text())
    assert Path(producer["module_path"]).resolve().is_relative_to(state / "venv")
    module = Path(unquote(urlparse(consumer["module_path"]).path)).resolve()
    installed_node = state / "app/node_modules/@chio-protocol/process"
    assert module == installed_node / "index.mjs"
    original = (state / "receipts.ndjson").read_bytes()
    receipt_rows = [json.loads(line) for line in original.splitlines()]
    # Signature verification was performed by the copied CLI before reading
    # these signed fields. SDK response verdicts alone are not the oracle.
    assert sum(row["decision"]["verdict"] == "deny" for row in receipt_rows) == 2
    assert sum(row["decision"]["verdict"] == "allow" for row in receipt_rows) == 3
    denials = [row for row in receipt_rows if row["decision"]["verdict"] == "deny"]
    assert {row["tool_name"] for row in denials} == {"receive_jobs", "send_jobs"}
    assert all("not in capability scope" in row["decision"]["reason"] for row in denials)
    with sqlite3.connect(state / "host/mailboxes.db") as db:
        assert db.execute(
            "SELECT last_sequence, acknowledged_through FROM mailboxes"
        ).fetchall() == [(1, 1)]
        assert db.execute("SELECT count(*), count(payload) FROM mailbox_messages").fetchone() == (
            1,
            0,
        )
    outputs = list((state / "app").glob("producer-*.json")) + [state / "app/consumer.json"]
    mtimes = {path: path.stat().st_mtime_ns for path in outputs}
    repeat = json.loads(command(invoke, work, env))
    assert repeat == evidence
    assert (state / "receipts.ndjson").read_bytes() == original
    assert mtimes == {path: path.stat().st_mtime_ns for path in outputs}

    # Run the protocol tests against the installed wheel and tarball, with
    # their original relative Node import now pointing inside node_modules.
    tests = work / "python-tests"
    shutil.copytree(ROOT / "sdks/python/chio-process/tests", tests)
    python = state / "venv/bin/python"
    command([python, "-I", "-m", "unittest", "discover", "-s", tests], work, env)
    shutil.copytree(ROOT / "sdks/typescript/packages/process/test", installed_node / "test")
    command(["node", "--test", *sorted((installed_node / "test").glob("*.test.mjs"))], work, env)

    # Rebuild only from the sdist, install that wheel into a second external
    # environment and run the same behavioral protocol tests there.
    rebuilt = work / "rebuilt"
    command(
        ["uv", "build", "--wheel", next((kit / "packages").glob("*.tar.gz")), "--out-dir", rebuilt],
        work,
        env,
    )
    venv.EnvBuilder(with_pip=True).create(work / "sdist-venv")
    sdist_python = work / "sdist-venv/bin/python"
    command(
        [
            sdist_python,
            "-I",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
            next(rebuilt.glob("*.whl")),
        ],
        work,
        env,
    )
    command([sdist_python, "-I", "-m", "unittest", "discover", "-s", tests], work, env)

    source = kit / "producer.py"
    saved = source.read_bytes()
    try:
        source.write_bytes(saved + b"\n# changed application\n")
        command(invoke, work, env, success=False)
    finally:
        source.write_bytes(saved)
    exported = kit / "evidence"
    exported.mkdir()
    for name in ("receipts.ndjson", "kernel.pub", "result.json"):
        shutil.copyfile(state / name, exported / name)
    write(
        exported / "qualification.json",
        {
            "schema": "chio.process.package-qualification.v1",
            "python": platform.python_version(),
            "node": command(["node", "--version"], work, env).strip(),
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "checks": [
                "offline_local_artifact_install",
                "external_python_and_node_imports",
                "python_to_node_mailbox",
                "known_handoff_replays_original_receipts",
                "five_verified_receipts_including_two_scope_denials",
                "one_acknowledged_message",
                "completed_run_does_not_respawn_workers",
                "native_operator_status_and_attempt_logs",
                "installed_wheel_and_tarball_protocol_tests",
                "rebuilt_sdist_protocol_tests",
                "artifact_drift_rejected",
            ],
        },
    )


def main():
    if not __debug__:
        raise SystemExit("Run qualification without Python optimization so assertions are active")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--chio", type=Path, required=True, help="built native CLI for this Linux host"
    )
    parser.add_argument(
        "--output", type=Path, required=True, help="new directory outside the checkout"
    )
    args = parser.parse_args()
    assert sys.platform == "linux", "native runner qualification requires Linux"
    os.umask(0o077)
    kit = args.output.resolve()
    assert not kit.is_relative_to(ROOT), "qualification output must be outside the checkout"
    kit.mkdir(mode=0o700)
    packages = kit / "packages"
    packages.mkdir()
    (kit / "bin").mkdir()
    shutil.copy2(args.chio.resolve(), kit / "bin/chio")
    for name in ("producer.py", "consumer.mjs", "run.py", "README.md", "ARCHITECTURE.md"):
        shutil.copyfile(ROOT / "examples/process-starter" / name, kit / name)
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("PYTHON") and key not in ("NODE_PATH", "NODE_OPTIONS")
    }
    command(
        [
            "uv",
            "build",
            "--sdist",
            "--wheel",
            ROOT / "sdks/python/chio-process",
            "--out-dir",
            packages,
        ],
        kit,
        env,
    )
    node_package = ROOT / "sdks/typescript/packages/process"
    command(["npm", "run", "build"], node_package, env)
    command(["npm", "pack", "--pack-destination", packages, "--json"], node_package, env)
    wheel = next(packages.glob("*.whl"))
    with zipfile.ZipFile(wheel) as archive:
        assert "chio_process/py.typed" in archive.namelist()
    # These local hashes detect accidental artifact drift. They are not a
    # signature or release provenance for the supplied host executable.
    write(
        kit / "manifest.json",
        {
            "schema": "chio.process.starter-artifacts.v1",
            "kind": "development-preview",
            "system": platform.system(),
            "machine": platform.machine(),
            "source_checkout": {
                "revision": command(["git", "rev-parse", "HEAD"], ROOT, env).strip(),
                "dirty": bool(command(["git", "status", "--porcelain"], ROOT, env)),
            },
            "files": {
                str(path.relative_to(kit)): digest(path)
                for path in sorted(kit.rglob("*"))
                if path.is_file()
            },
        },
    )
    work = Path(tempfile.mkdtemp(prefix="chio-pkg-"))
    try:
        qualify(kit, work, env)
    except BaseException:
        print(f"Qualification failed. Private diagnostic state retained at {work}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(work)
    print(f"Process package qualification passed. Starter and nonsecret evidence: {kit}")


if __name__ == "__main__":
    main()

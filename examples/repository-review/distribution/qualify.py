"""Qualify an extracted kit without importing code or dependencies from its checkout."""

import argparse
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def command(args, cwd, *, success=True):
    env = {
        key: value for key, value in os.environ.items() if not key.startswith("PYTHON")
    }
    # Offline installation must not depend on a working package registry.
    env.update(
        {
            "PIP_INDEX_URL": "http://127.0.0.1:1",
            "PIP_EXTRA_INDEX_URL": "http://127.0.0.1:1",
        }
    )
    result = subprocess.run(
        list(map(str, args)),
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    return result


def fixture(temporary):
    repo = temporary / "repo"
    repo.mkdir()
    command(["git", "init", "-q", repo], temporary)
    for value in (1, 2):
        for name in ("api/main.py", "api/test_main.py", "web/index.py"):
            path = repo / name
            path.parent.mkdir(exist_ok=True)
            path.write_text(f"value = {value}\n")
        command(["git", "-C", repo, "add", "."], temporary)
        command(
            [
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
                str(value),
            ],
            temporary,
        )
    return repo


def interrupted_run(kit, state, app, temporary):
    # Pin a known-spawn hold before the first native plan binding. Fault oracles
    # are qualification data; the application never reads them during recovery.
    command(
        [
            state / "venv/bin/python",
            "-c",
            """
import json, sys
from pathlib import Path
from adaptive.configuration import plan
from adaptive.common import persist
directory = Path(sys.argv[1])
config = json.loads((directory / 'run.json').read_text())
config.update(faults={'coordinator': 'spawn'}, fault_hold=True)
persist(directory / 'run.json', config)
persist(directory / 'worker-plan.json', plan(config, directory))
""",
            state / "run",
        ],
        kit / "application",
    )
    oracle = state / "run/workers/coordinator/first-spawn.json"
    with (state / "interrupted-launcher.log").open("wb") as log:
        process = subprocess.Popen(
            list(map(str, [*app, "run", "--state", state])),
            cwd=temporary,
            stdout=log,
            stderr=log,
        )
        try:
            deadline = time.monotonic() + 90
            while not oracle.exists():
                assert process.poll() is None, (
                    "launcher exited before the known spawn result"
                )
                assert time.monotonic() < deadline, "known spawn result did not arrive"
                time.sleep(0.05)
            original = json.loads(oracle.read_text())
            oracle.unlink()
            worker = json.loads(
                (state / "run/workers/coordinator/started-1.json").read_text()
            )["pid"]

            def parent(pid):
                return int(
                    Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1].split()[1]
                )

            native = parent(worker)
            application = parent(native)
            assert parent(application) == process.pid
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=60) == 130
            deadline = time.monotonic() + 10
            for pid in (worker, native, application):
                while True:
                    try:
                        if (
                            Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0]
                            == "Z"
                        ):
                            break
                    except (FileNotFoundError, ProcessLookupError):
                        break
                    assert time.monotonic() < deadline, (
                        "a supervised process outlived the interrupted launcher"
                    )
                    time.sleep(0.05)
            return original
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)


def exercise(kit, temporary):
    repo = fixture(temporary)
    state = temporary / "state"
    app = [sys.executable, "-I", kit / "review.py"]
    command(
        [
            *app,
            "prepare",
            "--state",
            state,
            "--repo",
            repo,
            "--base",
            "HEAD~1",
            "--max-parallel",
            "1",
        ],
        temporary,
    )
    (repo / "api/main.py").write_text("uncommitted = 'not captured'\n")
    original = interrupted_run(kit, state, app, temporary)
    command([*app, "run", "--state", state], temporary)
    evidence = json.loads((state / "run/evidence.json").read_text())
    assert evidence["receipt_verification"]["receipts_verified"] == 17
    assert evidence["publications"] == 1 and len(evidence["children"]) == 2
    assert all(
        receipt in evidence["workers"]["coordinator"]["receipts"]
        for receipt in original
    )
    installation = json.loads((state / "installation.json").read_text())
    assert all(
        Path(path).is_relative_to(state / "venv")
        for path in installation["runtime"]["modules"].values()
    )
    assert "langgraph-checkpoint-sqlite" in installation["runtime"]["packages"]
    assert not {"pytest", "ruff", "mypy"} & set(installation["runtime"]["packages"])
    command([*app, "run", "--state", state], temporary)
    repeated = json.loads((state / "run/evidence.json").read_text())
    assert (
        repeated["workers"] == evidence["workers"]
        and repeated["runner"] == evidence["runner"]
    )

    installed = Path(installation["runtime"]["modules"]["chio_process"])
    saved = installed.read_bytes()
    try:
        # This invalid Python must be rejected by the outer stdlib launcher
        # before importing the modified SDK.
        installed.write_bytes(saved + b"\nthis is invalid Python !\n")
        rejected = command([*app, "run", "--state", state], temporary, success=False)
        assert "installed file changed" in rejected.stderr
    finally:
        installed.write_bytes(saved)
    source = kit / "application/adaptive/graphs.py"
    saved = source.read_bytes()
    try:
        source.write_bytes(saved + b"\n# changed application\n")
        assert (
            "artifact changed"
            in command([*app, "run", "--state", state], temporary, success=False).stderr
        )
    finally:
        source.write_bytes(saved)
    with sqlite3.connect(state / "run/publications.db") as db:
        assert db.execute("SELECT count(*) FROM reports").fetchone()[0] == 1

    output = kit / "evidence"
    output.mkdir(mode=0o700, exist_ok=False)
    for name in ("report.md", "evidence.json", "receipts.ndjson", "kernel.pub"):
        shutil.copyfile(state / "run" / name, output / name)
    command(
        [
            state / "venv/bin/python",
            kit / "application/qualify_adaptive.py",
            "--chio",
            kit / "bin/chio",
            "--output",
            output / "recovery",
        ],
        temporary,
    )
    recovery = json.loads((output / "recovery/qualification.json").read_text())
    assert len(recovery["profiles"]) == 4 and len(recovery["rejected"]) == 2
    summary = {
        "schema": "chio.repository.review-kit-qualification.v1",
        "offline_install": True,
        "installed_imports": installation["runtime"]["modules"],
        "installed_packages": installation["runtime"]["packages"],
        "fixture_receipts_verified": 17,
        "fixture_publications": 1,
        "completed_workers_unchanged": True,
        "installed_sdk_drift_rejected_before_import": True,
        "application_drift_rejected": True,
        "launcher_termination_and_original_spawn_recovery": True,
        "adaptive_recovery": recovery,
        "live_model_called": False,
    }
    (output / "qualification.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(
        json.dumps(
            {
                "qualified": str(kit),
                "receipts_verified": 17,
                "recovery_profiles": 4,
                "rejection_profiles": 2,
            }
        )
    )


def main():
    if not __debug__:
        raise SystemExit("run qualification without Python optimization")
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--kit", type=Path, required=True)
    args = parser.parse_args()
    temporary = Path(tempfile.mkdtemp(prefix="chio-rkit-"))
    try:
        exercise(args.kit.resolve(strict=True), temporary)
    except BaseException:
        print(f"Preserved private failure state: {temporary}", file=sys.stderr)
        raise
    else:
        shutil.rmtree(temporary)


if __name__ == "__main__":
    main()

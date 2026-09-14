"""Declare the worker application for the native Chio process runner."""

import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def plan(config, directory):
    return {
        "schema": "chio.process.run.v1",
        "max_parallel": 2,
        "workers": [
            {
                "process": role,
                "command": [sys.executable, str(HERE / "worker.py")],
                "cwd": str(HERE),
                "input": {**config, "role": role, "directory": str(directory / role)},
                "depends_on": ["changes", "tests"] if role == "publisher" else [],
                "max_attempts": 3,
                "timeout_seconds": 600,
            }
            for role in ("changes", "tests", "publisher")
        ],
    }


def run(config, directory):
    with (directory / "host-error.log").open("ab") as errors:
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
            stdout=subprocess.PIPE,
            stderr=errors,
        )
        try:
            output, _ = process.communicate(timeout=3660)
            if process.returncode:
                raise RuntimeError(
                    "native worker run stopped; inspect private host-error.log"
                )
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate(timeout=10)
    report = json.loads(output)
    if not report["complete"]:
        raise RuntimeError("native worker run is incomplete")
    return report

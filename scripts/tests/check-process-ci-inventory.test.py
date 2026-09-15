#!/usr/bin/env python3
"""Require strict process-state linting and dependency-parser tests in their lane."""

import shlex
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
workflow = yaml.safe_load((ROOT / ".github/workflows/process-workers.yml").read_text())
steps = workflow["jobs"]["host"]["steps"]
commands = [
    shlex.split(line) for step in steps for line in step.get("run", "").splitlines()
]
clippy = [command for command in commands if command[:2] == ["cargo", "clippy"]]
assert any(
    "--test" in command
    and any(
        command[index : index + 2] == ["--test", "process_state"]
        for index in range(len(command))
    )
    and command[-3:] == ["--", "-D", "warnings"]
    for command in clippy
), "process_state must be a strict Clippy target"
gate_step = next(
    step
    for step in steps
    if "python3 scripts/check-process-dependencies.py" in step.get("run", "")
)
assert "python3 scripts/tests/check-process-dependencies.test.py" in gate_step["run"], (
    "dependency parser fixtures must run beside the gate"
)
print("process CI inventory passed")

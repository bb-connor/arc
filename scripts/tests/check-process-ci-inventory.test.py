#!/usr/bin/env python3
"""Require strict process-state linting and dependency-parser tests in their lane."""

import shlex
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
workflow = yaml.safe_load((ROOT / ".github/workflows/process-workers.yml").read_text())
triggers = workflow.get("on", workflow.get(True))
for event in ("push", "pull_request"):
    for owner in ("chio-secret-broker", "chio-cage", "chio-cage-plan", "chio-cage-init"):
        assert f"crates/security/{owner}/**" in triggers[event]["paths"], (
            f"{owner} changes must trigger native consumer qualification"
        )
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
assert [
    "python3",
    "-m",
    "unittest",
    "discover",
    "-s",
    "sdks/typescript/packages/ai-sdk-process/qualification",
    "-p",
    "test_*.py",
] in commands, "installed AI SDK qualification must test executable snapshot integrity"
native_index = next(
    i
    for i, step in enumerate(steps)
    if step.get("uses") == "./.github/actions/enforced-native-fixture"
)
ordinary_index = next(
    i
    for i, step in enumerate(steps)
    if "cargo test --locked -p chio-cli --test process_host\n" in step.get("run", "")
)
assert ordinary_index < native_index, (
    "ordinary worker tests must run independently of native qualification"
)
assert any(
    "--features real-linux-enforcement --test process_host_native"
    in step.get("run", "")
    for step in steps[native_index + 1 :]
)
fixture = yaml.safe_load(
    (ROOT / ".github/actions/enforced-native-fixture/action.yml").read_text()
)
probe = fixture["runs"]["steps"][1]["run"]
assert (
    "--exact privileged_discovery_enforces_identity_filesystem_deadline_and_cleanup"
    in probe
)
assert "1 passed; 0 failed" in probe, "a skipped or empty probe cannot qualify the host"
assert "prepare-enforced-native-fixture.py" in fixture["runs"]["steps"][2]["run"]
assert '--read-path "$GITHUB_WORKSPACE"' not in fixture["runs"]["steps"][2]["run"], (
    "native fixture must not expose checkout metadata through a workspace-wide grant"
)
runtime = fixture["runs"]["steps"][2]["run"]
assert "prepare-native-python-runtime.py" in runtime
assert "CHIO_CAGE_RUNTIME_FILES_FILE" in runtime
for broad in ("/usr", "/opt/hostedtoolcache", "$GITHUB_WORKSPACE"):
    assert f'--read-path "{broad}"' not in runtime
for job in ("host", "optimized-comparison"):
    job_steps = workflow["jobs"][job]["steps"]
    assert any(step.get("uses") == "./.github/actions/prepared-native-broker" for step in job_steps)
    assert any(step.get("uses") == "./.github/actions/enforced-native-fixture" for step in job_steps)
broker = yaml.safe_load((ROOT / ".github/actions/prepared-native-broker/action.yml").read_text())
broker_build = broker["runs"]["steps"][0]["run"]
for name in ("CHIO_BROKER_TEST_BINARY", "CHIO_BROKER_MCP_TOOL", "CHIO_DOCKER_ADAPTER", "CHIO_REPOSITORY_ADAPTER"):
    assert name in broker_build
installed = next(step["run"] for step in steps if step.get("name") == "Repository review through the public process host")
assert "--reinstall --no-deps" in installed and "chio_process-0.1.0-py3-none-any.whl" in installed
assert "--no-sync" in installed, "qualification must retain the freshly built SDK wheel"
print("process CI inventory passed")

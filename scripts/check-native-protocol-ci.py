#!/usr/bin/env python3
"""Require qualified native fixtures before every native protocol CI consumer."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ACTION = "./.github/actions/enforced-native-fixture"
FIXTURE_NAME = "Qualify enforcing host and prepare native consumer fixture"
PROTOCOL_NAME = "Native protocol targets under enforced authority"
PROTOCOL_RUN = (
    "cargo test --locked -p chio-cli --features real-linux-enforcement "
    "--no-fail-fast --test mcp_auth_server --test mcp_serve "
    "--test mcp_serve_http --test conformance_cli"
)
CPP_NAME = "Run live C++ conformance areas"
CPP_RUN = (
    "cargo build --locked -p chio-cli --features real-linux-enforcement --bin chio\n"
    "cargo test --locked -p chio-conformance --no-fail-fast "
    "--test mcp_core_cpp_live --test tasks_cpp_live --test auth_cpp_live "
    "--test notifications_cpp_live --test nested_callbacks_cpp_live -- --nocapture"
)
SDK_NAME = "Run SDK parity"
SDK_RUN = (
    'CMAKE_PREFIX_PATH="$(./scripts/setup-drogon-test-deps.sh)"\n'
    "export CMAKE_PREFIX_PATH\n"
    "./scripts/check-sdk-parity.sh"
)
SDK_COMMANDS = (
    "./scripts/check-bindings-parity.sh",
    "./scripts/check-chio-py.sh",
    "./scripts/check-chio-go.sh",
    'CHIO_CPP_REQUIRE_CBINDGEN="${CHIO_CPP_REQUIRE_CBINDGEN:-0}" ./scripts/check-chio-cpp.sh',
    "./scripts/check-chio-drogon.sh",
    CPP_RUN.splitlines()[0],
    "CHIO_CPP_LIVE_CONFORMANCE=1 " + CPP_RUN.splitlines()[1],
)
POSTGRES_NAME = "Exercise the public worker role and actual native process host"
POSTGRES_RUN = (
    'python3 examples/postgres-job-swarm/check_api.py --database-state "$CHIO_JOB_FIXTURE_ROOT/database/state.json"\n'
    '"$CHIO_JOB_FIXTURE_ROOT/venv/bin/python" examples/postgres-job-swarm/qualify.py --chio "$CHIO_JOB_FIXTURE_ROOT/chio" --database-state "$CHIO_JOB_FIXTURE_ROOT/database/state.json" --output "$CHIO_JOB_FIXTURE_ROOT/qualification"'
)
POSTGRES_CLAIM_NAME = "Lose a committed claim response and recover without redispatch"
POSTGRES_CLAIM_RUN = (
    '"$CHIO_JOB_FIXTURE_ROOT/venv/bin/python" examples/postgres-job-swarm/qualify_claim_loss.py --chio "$CHIO_JOB_FIXTURE_ROOT/chio" --database-state "$CHIO_JOB_FIXTURE_ROOT/database/state.json" --output "$CHIO_JOB_FIXTURE_ROOT/claim-loss"'
)
COMMON_ENV = {
    "CARGO_BUILD_JOBS": "1",
    "RUSTFLAGS": "${{ env.CHIO_CI_RUSTFLAGS }} -C debuginfo=0",
}
# Bind the reviewed helper build, terminal privileged probe, bounded Python
# closure and validated authority grants, including their execution order.
FIXTURE_ACTION_SHA256 = "7f2085f2912ce7f87bbb861d5a33b6f7f89c7f2e6f38568e4ef7a301e4a3e4e7"
NATIVE_ENV = {
    "CHIO_CAGE_INIT",
    "CHIO_RECEIPT_ANCHOR_ROOT",
    "CHIO_CAGE_READ_PATHS_FILE",
    "CHIO_CAGE_RUNTIME_FILES_FILE",
    "CHIO_CAGE_EXECUTION_UID",
    "CHIO_CAGE_EXECUTION_GID",
    "CHIO_CAGE_EXECUTION_SUPPLEMENTARY_GIDS",
    "CHIO_CAGE_SYSCALL_PROFILE",
    "CHIO_DEMO_PYTHON",
}


class ContractError(ValueError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def named_step(job: dict, name: str) -> tuple[int, dict]:
    matches = [
        (index, step)
        for index, step in enumerate(job.get("steps", []))
        if step.get("name") == name
    ]
    require(len(matches) == 1, f"expected one native consumer step: {name}")
    return matches[0]


def validate_consumer(
    workflow: dict, job_id: str, consumer: str, fixture: dict, job_condition: str | None = None
) -> None:
    job = workflow["jobs"][job_id]
    require(
        "continue-on-error" not in job
        and (
            (job_condition is None and "if" not in job)
            or (job_condition is not None and job.get("if") == job_condition)
        ),
        f"{job_id}: containing job can skip or tolerate native failure",
    )
    require(
        job.get("runs-on") in ("ubuntu-latest", "ubuntu-24.04")
        and "container" not in job,
        f"{job_id}: native consumers require the Linux x86_64 host runner",
    )
    index, step = named_step(job, consumer)
    require(
        index > 0 and job["steps"][index - 1] == fixture,
        f"{job_id}: qualified fixture must run unconditionally immediately before {consumer}",
    )
    require(
        "if" not in step and "continue-on-error" not in step,
        f"{job_id}: native consumer cannot be skipped or tolerate failure",
    )
    for owner in (workflow, job, step):
        require(
            not (set(owner.get("env", {})) & NATIVE_ENV),
            f"{job_id}: native consumer overrides qualified fixture authority",
        )


def validate(
    ci: dict, process: dict, action: dict, cpp: dict, sdk: dict, postgres: dict,
    sdk_script: str,
) -> None:
    checks = (
        "python3 scripts/check-native-protocol-ci.py",
        "python3 scripts/tests/check-native-protocol-ci.test.py",
        "python3 scripts/tests/prepare-enforced-native-fixture.test.py",
    )
    _, structural = named_step(ci["jobs"]["check"], "Workspace structural gates")
    _, process_gate = named_step(
        process["jobs"]["host-tests"], "Default kernel and worker dependency boundary"
    )
    for command in checks:
        require(
            f"run_gate {command}" in structural["run"].splitlines()
            and command in process_gate["run"].splitlines(),
            f"native protocol CI omits required contract check: {command}",
        )
    for job_id, consumer, env in (
        ("check", "Workspace tests", COMMON_ENV),
        (
            "msrv",
            "MSRV workspace lane",
            {**COMMON_ENV, "CARGO_TARGET_DIR": "${{ runner.temp }}/chio-msrv-target"},
        ),
    ):
        validate_consumer(
            ci,
            job_id,
            consumer,
            {"name": FIXTURE_NAME, "uses": FIXTURE_ACTION, "env": env},
        )
    validate_consumer(
        process,
        "host-tests",
        PROTOCOL_NAME,
        {"name": FIXTURE_NAME, "id": "native_fixture", "uses": FIXTURE_ACTION},
        "${{ github.event_name != 'workflow_dispatch' || !inputs.optimized_comparison }}",
    )
    index, step = named_step(process["jobs"]["host-tests"], PROTOCOL_NAME)
    require(
        {**step, "run": step.get("run", "").strip()} == {
            "name": PROTOCOL_NAME,
            "env": {"RUST_TEST_THREADS": "1"},
            "run": PROTOCOL_RUN,
        },
        "native protocol target set must execute every required target with enforcement",
    )
    report_index, _ = named_step(
        process["jobs"]["host-tests"], "Native MCP and worker recovery under enforced authority"
    )
    require(index < report_index, "native protocol targets must precede static report setup")
    validate_consumer(
        cpp,
        "conformance",
        CPP_NAME,
        {"name": FIXTURE_NAME, "uses": FIXTURE_ACTION},
    )
    _, step = named_step(cpp["jobs"]["conformance"], CPP_NAME)
    require(
        {**step, "run": step.get("run", "").strip()} == {
            "name": CPP_NAME,
            "env": {"CHIO_CPP_LIVE_CONFORMANCE": "1"},
            "run": CPP_RUN,
        },
        "C++ target set must build the enforcing CLI and execute every live target",
    )
    validate_consumer(
        sdk, "sdk-parity", SDK_NAME, {"name": FIXTURE_NAME, "uses": FIXTURE_ACTION}
    )
    _, step = named_step(sdk["jobs"]["sdk-parity"], SDK_NAME)
    require(
        {**step, "run": step.get("run", "").strip()}
        == {"name": SDK_NAME, "run": SDK_RUN},
        "SDK parity must execute the complete native consumer script",
    )
    # Bind the shell command sequence after the feature-matrix heredoc. An
    # earlier Drogon build replaces the CLI, so the enforcing rebuild must
    # happen afterward and immediately precede the five native test targets.
    sections = sdk_script.split("\nEOF\n")
    require(
        sdk_script.startswith("#!/usr/bin/env bash\nset -euo pipefail\n")
        and len(sections) == 2
        and not any(variable in sdk_script for variable in NATIVE_ENV),
        "SDK parity must retain failure propagation and qualified fixture authority",
    )
    commands = tuple(
        line.strip()
        for line in sections[1].split("\necho ", 1)[0].splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    require(
        commands == SDK_COMMANDS,
        "SDK parity must preserve earlier checks, rebuild enforcement after Drogon and execute all live areas",
    )
    validate_consumer(
        postgres, "native", POSTGRES_NAME,
        {"name": FIXTURE_NAME, "uses": FIXTURE_ACTION},
    )
    job = postgres["jobs"]["native"]
    consumer_index, step = named_step(job, POSTGRES_NAME)
    require(
        consumer_index >= 2
        and job["steps"][consumer_index - 2] == {
            "name": "Build prepared native broker transports",
            "uses": "./.github/actions/prepared-native-broker",
        },
        "prepared PostgreSQL broker transports must precede the enforcing fixture unconditionally",
    )
    build_index, build = named_step(job, "Build the real gateway and kernel")
    copy_index, copy = named_step(job, "Install the process package and create a dedicated TLS fixture")
    require(
        build_index < copy_index < consumer_index - 1
        and "if" not in build and "continue-on-error" not in build
        and "if" not in copy and "continue-on-error" not in copy
        and build.get("run", "").strip().splitlines()[-1:] == [CPP_RUN.splitlines()[0]]
        and 'cp target/debug/chio "$job_root/chio"' in copy.get("run", "").splitlines(),
        "PostgreSQL enforcing CLI must be built before copying the consumer binary",
    )
    claim_index, claim = named_step(job, POSTGRES_CLAIM_NAME)
    require(
        {**step, "run": step.get("run", "").strip()}
        == {"name": POSTGRES_NAME, "run": POSTGRES_RUN}
        and claim_index == consumer_index + 1
        and {**claim, "run": claim.get("run", "").strip()}
        == {"name": POSTGRES_CLAIM_NAME, "run": POSTGRES_CLAIM_RUN},
        "PostgreSQL qualification must execute both native consumers in order without authority overrides",
    )
    digest = hashlib.sha256(
        json.dumps(action, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    require(
        digest == FIXTURE_ACTION_SHA256,
        "native fixture action changes reviewed host, runtime or authority preparation",
    )


def main() -> None:
    validate(
        yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text()),
        yaml.safe_load((ROOT / ".github/workflows/process-workers.yml").read_text()),
        yaml.safe_load((ROOT / ".github/actions/enforced-native-fixture/action.yml").read_text()),
        yaml.safe_load((ROOT / ".github/workflows/chio-cpp.yml").read_text()),
        yaml.safe_load((ROOT / ".github/workflows/sdk-parity.yml").read_text()),
        yaml.safe_load((ROOT / ".github/workflows/postgres-job-swarm.yml").read_text()),
        (ROOT / "scripts/check-sdk-parity.sh").read_text(),
    )
    print("native protocol CI contract passed: workspace, CLI, C++, SDK parity and PostgreSQL consumers")


if __name__ == "__main__":
    main()

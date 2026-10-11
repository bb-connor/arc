"""Qualify actual file confinement through the governed process supervisor.

The explicitly built enforcement-probe example attempts raw OS reads/writes.
An unconfined positive control proves both effects are possible; the same
executable must then return EACCES under Enforced launch. This is one M5 slice.
"""

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def control(probe, tool, path):
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": tool, "arguments": {"path": str(path)}},
    }
    result = subprocess.run(
        [str(probe)],
        input=json.dumps(request) + "\n",
        text=True,
        capture_output=True,
        timeout=30,
        check=True,
    )
    return json.loads(result.stdout)["result"]["structuredContent"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in [
        "chio",
        "cage-init",
        "probe",
        "output",
        "receipt-rollback-anchor-root",
    ]:
        parser.add_argument(f"--{name}", type=Path, required=True)
    parser.add_argument("--worker-image", required=True)
    args = parser.parse_args()
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        parser.error("requires the supported Linux x86_64 cage profile")
    if os.getuid() == 0 or os.getgid() == 0:
        parser.error("run as a non-root operator")
    os.umask(0o077)
    chio, helper, probe = [
        path.resolve(strict=True) for path in [args.chio, args.cage_init, args.probe]
    ]
    anchor = args.receipt_rollback_anchor_root.resolve(strict=True)
    if not anchor.is_dir() or anchor.stat().st_mode & 0o077:
        parser.error("receipt rollback anchor must be a private existing directory")
    output = args.output.absolute()
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    output = output.resolve(strict=True)
    inputs = output / "allowed"
    inputs.mkdir(mode=0o700)
    protected = output / "protected"
    protected.mkdir(mode=0o700)
    public = inputs / "canary.txt"
    public.write_text("allowed-reference-content\n")
    secret = protected / "secret.txt"
    secret.write_text("private-" + os.urandom(32).hex() + "\n")
    sentinel = protected / "must-not-change.txt"
    sentinel.write_text("original-protected-content\n")
    before = sentinel.read_bytes()
    read_control = control(probe, "read_file", secret)
    assert read_control == {
        "effect": "succeeded",
        "value": {"bytes_hex": secret.read_bytes().hex()},
    }, read_control
    write_control = control(probe, "write_file", sentinel)
    assert write_control["effect"] == "succeeded", write_control
    assert sentinel.read_bytes() == b"probe-effect\n"
    sentinel.write_bytes(before)
    # Retain hashes and outcomes, not the unconfined secret response.
    write(
        output / "controls.json",
        {
            "probe_sha256": digest(probe),
            "read_succeeded": True,
            "write_succeeded": True,
            "secret_sha256": digest(secret),
            "sentinel_sha256": digest(sentinel),
        },
    )
    commands = []

    def run(label, command):
        completed = subprocess.run(
            list(map(str, command)),
            text=True,
            capture_output=True,
            check=False,
            timeout=600,
        )
        (output / f"{label}.stdout").write_text(completed.stdout)
        (output / f"{label}.stderr").write_text(completed.stderr)
        commands.append(
            {
                "stage": label,
                "command": list(map(str, command)),
                "exit": completed.returncode,
            }
        )
        (output / "commands.json").write_text(json.dumps(commands, indent=2) + "\n")
        if completed.returncode:
            raise RuntimeError(
                f"{label} failed; inspect {output / (label + '.stderr')}"
            )
        return json.loads(completed.stdout)

    launch = output / "launch"
    provision = [
        chio,
        "security",
        "provision-reference-runtime",
        "--output-dir",
        launch,
        "--cage-init",
        helper,
        "--target",
        probe,
        "--working-directory",
        inputs,
        "--read-path",
        inputs,
        "--max-artifact-bytes",
        "2097152",
        "--receipt-rollback-anchor-root",
        anchor,
        "--discover-tools",
        "--execution-uid",
        os.getuid(),
        "--execution-gid",
        os.getgid(),
        "--server-id",
        "filesystem-probe",
    ]
    for gid in sorted(set(os.getgroups()) - {os.getgid()}):
        provision.extend(["--execution-supplementary-gid", gid])
    run("provision", provision)
    policy_report = json.loads((launch / "provision-report.json").read_text())
    assert policy_report["securityMode"] == "enforced_cage", policy_report
    policy = output / "policy.yaml"
    policy.write_text("""kernel:
  max_capability_ttl: 3600
  durable_admission_mode: all
  require_swarm_admission: true
capabilities:
  default:
    tools:
      - server: filesystem-probe
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    calls = [
        ("canary", "read_file", public, 3334),
        ("forbidden-read", "read_file", secret, 3333),
        ("forbidden-write", "write_file", sentinel, 3333),
    ]
    config = {
        "schema": "chio.process.host.v1",
        "execution_nonces": True,
        "policy": str(policy),
        "servers": [
            {
                "id": "filesystem-probe",
                "command": [str(probe)],
                "launch_policy": str(launch / "cage-launch-policy.json"),
                "launch_policy_signer": policy_report["cagePolicyPublicKey"],
            }
        ],
        "limits": {"max_processes": 4, "max_depth": 1, "max_calls": 12},
        "children": [
            {
                "id": name,
                "parent": "root",
                "budget_share_bps": share,
                "tools": [{"server_id": "filesystem-probe", "tool_name": tool}],
            }
            for name, tool, _, share in calls
        ],
    }
    plan = {
        "schema": "chio.process.swarm-plan.v1",
        "graph_id": "filesystem-enforcement",
        "calls": [
            {
                "process": name,
                "operation_key": "observe-effect",
                "server_id": "filesystem-probe",
                "tool_name": tool,
                "arguments": {"path": str(path)},
            }
            for name, tool, path, _ in calls
        ],
    }
    write(output / "host.json", config)
    write(output / "plan.json", plan)
    state = output / "state"
    run(
        "initialize",
        [
            chio,
            "process",
            "init",
            "--config",
            output / "host.json",
            "--state",
            state,
            "--aggregate-invocations",
            3,
            "--swarm-plan",
            output / "plan.json",
        ],
    )
    evidence = output / "evidence"
    run(
        "workers",
        [
            sys.executable,
            Path(__file__).with_name("process-run.py"),
            "--chio",
            chio,
            "--state",
            state,
            "--output",
            evidence,
            "--worker-image",
            args.worker_image,
        ],
    )
    observations = {}
    for name, _, _, _ in calls:
        response = json.loads((evidence / name / "response.json").read_text())
        assert response["verdict"] == "allow", response
        observations[name] = response["output"]["value"]["structuredContent"]
    assert observations["canary"] == {
        "effect": "succeeded",
        "value": {"bytes_hex": public.read_bytes().hex()},
    }, observations
    for name in ["forbidden-read", "forbidden-write"]:
        assert observations[name] == {"effect": "refused", "os_errno": 13}, observations
    assert sentinel.read_bytes() == before, "forbidden write changed the protected file"
    assert all(
        secret.read_bytes().hex() not in json.dumps(value)
        for value in observations.values()
    ), "secret reached a worker"
    verification = json.loads(
        (evidence / "completed-run-verification.json").read_text()
    )
    assert verification["verified_native_launches"] == 1, verification
    assert verification["captured_invocations"] == 3, verification
    assert "continuation_custody" in verification["checks"], verification
    result = {
        "schema": "chio.reference-swarm.filesystem-qualification.v1",
        "probe_sha256": digest(probe),
        "cli_sha256": digest(chio),
        "worker_image": args.worker_image,
        "positive_controls": "controls.json",
        "completed_artifact_sha256": digest(evidence / "completed-run.json"),
        "observations": observations,
        "protected_file_unchanged": True,
        "secret_not_returned": True,
        "verification": verification,
        "m5_acceptance_complete": False,
    }
    write(output / "qualification.json", result)
    print(json.dumps(result))


if __name__ == "__main__":
    main()

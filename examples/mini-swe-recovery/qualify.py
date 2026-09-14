"""Real mini-SWE-agent, Docker commands, worker SIGKILL and fresh CLI host."""

import argparse
import contextlib
import hashlib
import inspect
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from chio_process.launch import demo_python, provision_native_demo
from minisweagent.agents.default import DefaultAgent

HERE = Path(__file__).resolve().parent


def command(*arguments, **kwargs):
    return subprocess.run(
        [str(argument) for argument in arguments],
        text=True,
        capture_output=True,
        check=True,
        timeout=120,
        **kwargs,
    ).stdout


@contextlib.contextmanager
def serving(binary, directory):
    with (directory / "host.log").open("a") as log:
        process = subprocess.Popen(
            [
                str(binary),
                "process",
                "serve",
                "--state",
                str(directory / "host"),
                "--socket",
                str(directory / "worker.sock"),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=log,
        )
        try:
            assert select.select([process.stdout], [], [], 90)[0], "host startup timed out"
            line = process.stdout.readline()
            assert line, (directory / "host.log").read_text()
            assert json.loads(line)["ready"]
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=10)
                raise


def exercise(binary, directory, image, worker_image=None):
    upstream_sha256 = hashlib.sha256(Path(inspect.getfile(DefaultAgent)).read_bytes()).hexdigest()
    assert upstream_sha256 == "e8ef8aa365942d739c2ec5cb0879f60f377d2dc2de8ec670aaedf3bafb45a4c2"
    container = command(
        "docker",
        "run",
        "-d",
        "--rm",
        "--network",
        "none",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--user",
        "65534:65534",
        "--memory",
        "256m",
        "--pids-limit",
        "64",
        "-e",
        "PYTHONDONTWRITEBYTECODE=1",
        "--tmpfs",
        "/workspace:rw,size=16m,mode=1777",
        "--tmpfs",
        "/tmp:rw,size=8m,mode=1777",
        "-w",
        "/workspace",
        image,
        "sleep",
        "1800",
    ).strip()
    try:
        command(
            "docker",
            "exec",
            "-i",
            container,
            "python",
            "-",
            input=(
                "from pathlib import Path\n"
                "Path('calculator.py').write_text('def add(a, b):\\n    return a - b\\n')\n"
                "Path('test_calculator.py').write_text('import unittest\\n"
                "from calculator import add\\n"
                "class Addition(unittest.TestCase):\\n    def test_positive(self):\\n"
                "        self.assertEqual(add(2, 3), 5)\\n    def test_negative(self):\\n"
                "        self.assertEqual(add(-2, -3), -5)\\n')\n"
            ),
        )
        initial = subprocess.run(
            ["docker", "exec", "-w", "/workspace", container, "python", "-m", "unittest"],
            text=True,
            capture_output=True,
            timeout=30,
        )
        assert initial.returncode == 1 and "FAILED (failures=2)" in initial.stderr
        (directory / "tests-before.txt").write_text(initial.stderr)
        policy = directory / "policy.yaml"
        policy.write_text("""kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 8
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: sandbox
        tool: execute
        operations: [invoke, delegate]
        ttl: 3600
""")
        server = provision_native_demo(
            binary,
            "sandbox",
            [demo_python(), str(HERE / "sandbox.py"), "--container", container],
            directory / "launch",
            directory,
        )
        config = {
            "schema": "chio.process.host.v1",
            "policy": str(policy),
            "servers": [server],
            "limits": {"max_calls": 8, "max_processes": 2, "max_depth": 1},
            "children": [
                {
                    "id": "coder",
                    "parent": "root",
                    "budget_share_bps": 9000,
                    "tools": [{"server_id": "sandbox", "tool_name": "execute"}],
                }
            ],
        }
        (directory / "config.json").write_text(json.dumps(config))
        initialized = json.loads(
            command(
                binary,
                "process",
                "init",
                "--config",
                directory / "config.json",
                "--state",
                directory / "host",
            )
        )
        command(
            binary,
            "process",
            "credential",
            "--state",
            directory / "host",
            "--process",
            "coder",
            "--socket",
            directory / "worker.sock",
            "--out",
            directory / "connection.json",
        )
        attempts = None
        if worker_image:
            from container_attempts import ContainerAttempts

            attempts = ContainerAttempts(worker_image, directory)
        with serving(binary, directory) as host:
            if attempts:
                attempts.probe()
            crashed = (
                attempts.run(crash=True)
                if attempts
                else subprocess.run(
                    [sys.executable, str(HERE / "worker.py"), str(directory)],
                    text=True,
                    capture_output=True,
                    timeout=120,
                )
            )
            (directory / "first-worker.log").write_text(crashed.stdout + crashed.stderr)
            expected_exit = 128 + signal.SIGKILL if attempts else -signal.SIGKILL
            assert crashed.returncode == expected_exit, (crashed.stdout, crashed.stderr)
            assert (
                command("docker", "exec", container, "cat", "/workspace/effects.txt") == "patched\n"
            )
            host.kill()
            host.wait(timeout=15)
        # Only after wait confirms this owned host is dead can its socket go.
        (directory / "worker.sock").unlink()
        with serving(binary, directory):
            if attempts:
                completed = attempts.run()
                assert completed.returncode == 0, completed.stdout
                resumed = completed.stdout
            else:
                resumed = command(sys.executable, HERE / "worker.py", directory)
            (directory / "resumed-worker.log").write_text(resumed)
            receipt_bytes = (directory / "receipts.ndjson").read_bytes()
            provider_bytes = (directory / "provider-calls.jsonl").read_bytes()
            if attempts:
                completed = attempts.run()
                assert completed.returncode == 0, completed.stdout
            else:
                command(sys.executable, HERE / "worker.py", directory)
            assert (directory / "receipts.ndjson").read_bytes() == receipt_bytes
            assert (directory / "provider-calls.jsonl").read_bytes() == provider_bytes
        effects = command("docker", "exec", container, "cat", "/workspace/effects.txt").splitlines()
        assert effects == ["patched", "audit", "audit"]
        receipts = (directory / "receipts.ndjson").read_text().splitlines()
        assert len(receipts) == len(set(receipts)) == 5
        assert (directory / "before-crash.receipt.json").read_text() in receipts
        assert len(provider_bytes.splitlines()) == 3
        result = json.loads((directory / "result.json").read_text())
        assert result["exit_status"] == "Submitted"
        after = command("docker", "exec", container, "cat", "/workspace/test-output.txt")
        assert "Ran 2 tests" in after and "\nOK\n" in after
        (directory / "tests-after.txt").write_text(after)
        (directory / "effects.json").write_text(json.dumps(effects))
        (directory / "kernel.pub").write_text(initialized["kernel_key"])
        verification = json.loads(
            command(
                binary,
                "receipt",
                "verify",
                "--input",
                directory / "receipts.ndjson",
                "--trusted-kernel-pubkey",
                directory / "kernel.pub",
                "--json",
            )
        )
        assert verification["receipts_verified"] == 5
        return {
            "upstream": "mini-swe-agent==2.4.6",
            "worker_boundary": attempts.evidence if attempts else {"profile": "same-user"},
            "upstream_agent_sha256": upstream_sha256,
            "provider": "saved tool-call fixture",
            "worker_sigkill": True,
            "host_sigkill": True,
            "provider_calls": 3,
            "distinct_receipts": 5,
            "verified_receipts": verification["receipts_verified"],
            "patch_effects": 1,
            "identical_audit_effects": 2,
            "tests_before": "2 failed",
            "tests_after": "2 passed",
            "completed_replay": True,
            "container_image": json.loads(command("docker", "inspect", container))[0]["Image"],
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        }
    finally:
        command("docker", "rm", "-f", container)


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default="python:3.11-slim")
    worker = parser.add_mutually_exclusive_group()
    worker.add_argument(
        "--worker-image", help="Immutable local image id for isolated Python workers"
    )
    worker.add_argument("--worker-image-file", type=Path, help="JSON from build_worker_image.py")
    args = parser.parse_args()
    worker_image = args.worker_image
    if args.worker_image_file:
        worker_image = json.loads(args.worker_image_file.read_text())["image"]
    args.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    directory = Path(tempfile.mkdtemp(prefix="chio-mini-"))
    try:
        result = exercise(args.chio.resolve(strict=True), directory, args.image, worker_image)
        result["private_state"] = str(directory)
        (args.output / "qualification.json").write_text(json.dumps(result, indent=2) + "\n")
        for name in [
            "receipts.ndjson",
            "kernel.pub",
            "tests-before.txt",
            "tests-after.txt",
            "effects.json",
            "trajectory.json",
            "provider-calls.jsonl",
        ]:
            (args.output / name).write_bytes((directory / name).read_bytes())
        print(json.dumps(result))
    finally:
        print(f"Private qualification state: {directory}", file=sys.stderr)


if __name__ == "__main__":
    main()

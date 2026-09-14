"""Installed mini-SWE-agent with native scheduling and mediated model queries."""

import argparse
import ctypes
import hashlib
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import sysconfig
import tempfile
import time
from pathlib import Path

from chio_mini_swe import ChioModel, ChioModelError
from chio_mini_swe.state import Journal
from chio_mini_swe.worker import SCHEMA, export_result
from chio_process import ProcessClient
from chio_process.launch import demo_python, provision_native_demo
from qualify import command, serving

HERE = Path(__file__).resolve().parent
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]

# Some standalone Python builds omit os.pidfd_open despite running on a
# supporting Linux host. Use libc's typed wrappers, never a recycled bare PID.
LIBC = ctypes.CDLL(None, use_errno=True)
LIBC.pidfd_open.argtypes = [ctypes.c_int, ctypes.c_uint]
LIBC.pidfd_open.restype = ctypes.c_int
LIBC.pidfd_send_signal.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint]
LIBC.pidfd_send_signal.restype = ctypes.c_int


def pidfd_open(pid):
    descriptor = LIBC.pidfd_open(pid, 0)
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), "Could not pin qualification gateway process")
    return descriptor


def kill_gateway(descriptor):
    if LIBC.pidfd_send_signal(descriptor, signal.SIGKILL, None, 0) < 0:
        raise OSError(ctypes.get_errno(), "Could not stop qualification gateway process")


def docker(*args, **kwargs):
    return command(*DOCKER, *args, **kwargs)


def prepare(binary, directory, base_image, worker_image, profile):
    directory.mkdir(mode=0o700)
    repository = docker(
        "run",
        "-d",
        "--network=none",
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65534:65534",
        "--memory=256m",
        "--memory-swap=256m",
        "--cpus=1",
        "--pids-limit=64",
        "--env=PYTHONDONTWRITEBYTECODE=1",
        "--tmpfs=/workspace:rw,size=16m,mode=1777",
        "--tmpfs=/tmp:rw,size=8m,mode=1777",
        "--workdir=/workspace",
        base_image,
        "sleep",
        "1800",
    ).strip()
    try:
        docker(
            "exec",
            "-i",
            repository,
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
      - server: model
        tool: model_infer
        operations: [invoke, delegate]
        ttl: 3600
""")
        for name in ("native_gateway.py", "worker.py", "sandbox.py"):
            shutil.copyfile(HERE / name, directory / name)
        servers = [
            provision_native_demo(
                binary,
                "sandbox",
                [demo_python(), str(directory / "sandbox.py"), "--container", repository],
                directory / "launch-sandbox",
                directory,
            )
        ]
        gateway = [
            sys.executable,
            str(directory / "native_gateway.py"),
            "--packages",
            sysconfig.get_path("purelib"),
            "--record",
            str(directory / "queries.jsonl"),
        ]
        if profile == "unknown":
            gateway.append("--unknown")
        servers.append(
            provision_native_demo(binary, "model", gateway, directory / "launch-model", directory)
        )
        config = {
            "schema": "chio.process.host.v1",
            "policy": str(policy),
            "servers": servers,
            "limits": {"max_calls": 12, "max_processes": 2, "max_depth": 1},
            "children": [
                {
                    "id": "coder",
                    "parent": "root",
                    "budget_share_bps": 9000,
                    "tools": [
                        {"server_id": "sandbox", "tool_name": "execute"},
                        {"server_id": "model", "tool_name": "model_infer"},
                    ],
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
        (directory / "kernel.pub").write_text(initialized["kernel_key"])
        worker_command = ["/usr/local/bin/chio-mini-swe-worker"]
        if profile == "known":
            worker_command = [
                "/usr/local/bin/python",
                "-u",
                "-c",
                (HERE / "native_fault_worker.py").read_text(),
            ]
        data = {
            "schema": SCHEMA,
            "run_id": "native-mini-repair",
            "task": "Fix addition and verify the existing unit tests.",
            "model": {
                "server_id": "model",
                "tool_name": "model_infer",
                "model_id": "saved-native-decisions-v1",
            },
            "environment": {
                "server_id": "sandbox",
                "tool_name": "execute",
                "template_vars": {"cwd": "/workspace"},
            },
            "agent": {
                "system_template": "Repair the Python repository using bash commands.",
                "instance_template": "{{task}}",
                "step_limit": 8,
                "cost_limit": 10,
                "wall_time_limit_seconds": 600,
            },
        }
        plan = {
            "schema": "chio.process.run.v1",
            "max_parallel": 1,
            "workers": [
                {
                    "process": "coder",
                    "command": worker_command,
                    "cwd": "/work",
                    "container": {"image": worker_image},
                    "input": data,
                    "max_attempts": 2 if profile == "unknown" else 3,
                    "timeout_seconds": 90,
                }
            ],
        }
        (directory / "plan.json").write_text(json.dumps(plan))
        return repository
    except BaseException:
        docker("rm", "--force", "--volumes", repository)
        raise


def launch(binary, directory):
    return subprocess.Popen(
        [
            str(binary),
            "process",
            "run",
            "--state",
            str(directory / "host"),
            "--plan",
            str(directory / "plan.json"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


def wait_until(process, read):
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        assert process.poll() is None, process.communicate()
        result = read()
        if result is not None:
            return result
        time.sleep(0.05)
    raise AssertionError("Native application readiness timed out")


def model_returned(directory):
    path = directory / "host/runner.db"
    if not path.exists():
        return None
    with sqlite3.connect(path) as db:
        if not db.execute("SELECT 1 FROM sqlite_master WHERE name='run_containers'").fetchone():
            return None
        row = db.execute(
            "SELECT container_id FROM run_containers WHERE process='coder' AND attempt=1"
        ).fetchone()
    if not row or not row[0]:
        return None
    result = subprocess.run(
        [*DOCKER, "exec", row[0], "cat", "/work/model-returned.json"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return (row[0], json.loads(result.stdout)) if result.returncode == 0 else None


def queries(directory):
    path = directory / "queries.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def finish(process, success=True):
    out, err = process.communicate(timeout=180)
    assert (process.returncode == 0) == success, (out, err)
    return json.loads(out), err


def read_state(binary, directory, unknown=False):
    descriptor = directory / "connection.json"
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
        descriptor,
    )
    connection = json.loads(descriptor.read_text())
    with serving(binary, directory):
        client = ProcessClient(connection["socket_path"], connection["credential"])
        if not unknown:
            return export_result(client)
        snapshot = Journal(client).read()
        assert snapshot["phase"] == "model_pending" and snapshot["n_calls"] == 0
        model = ChioModel(
            client, server_id="model", tool_name="model_infer", model_id="saved-native-decisions-v1"
        )
        model.bind("native-mini-repair", 1)
        try:
            model.query(snapshot["messages"])
        except ChioModelError as error:
            assert error.receipt_json
            receipt = json.loads(error.receipt_json)
            assert (
                receipt["metadata"]["admission_operation"]["retained_state"]
                == "outcome_unknown_after_dispatch"
            )
            assert receipt["metadata"]["chio_process"]["recovery_policy"] == "known_outcome_only"
            return {"unknown_receipt": error.receipt_json}
        raise AssertionError("Unknown model outcome was accepted")


def exercise(binary, directory, base, image, profile):
    repository = prepare(binary, directory, base, image, profile)
    host = None
    gateway_fd = None
    first = None
    try:
        initial = subprocess.run(
            [*DOCKER, "exec", repository, "python", "-m", "unittest"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert initial.returncode == 1 and "FAILED (failures=2)" in initial.stderr
        host = launch(binary, directory)
        if profile == "known":
            old_id, first = wait_until(host, lambda: model_returned(directory))
            assert len(queries(directory)) == 1
            host.kill()
            host.communicate(timeout=15)
            assert json.loads(docker("inspect", old_id))[0]["State"]["Running"]
            host = launch(binary, directory)
        elif profile == "unknown":
            started = wait_until(host, lambda: (queries(directory) or [None])[0])
            gateway_fd = pidfd_open(started["pid"])
            host.kill()
            host.communicate(timeout=15)
            try:
                kill_gateway(gateway_fd)
            except ProcessLookupError:
                pass
            host = launch(binary, directory)
        report, error = finish(host, success=profile != "unknown")
        (directory / "run-report.json").write_text(json.dumps(report))
        (directory / "run-stderr.txt").write_text(error)
        expected_attempts = {"baseline": 1, "known": 3, "unknown": 2}[profile]
        assert report["workers"][0]["attempts"] == expected_attempts
        assert report["pending_container_records"] == 0
        exported = read_state(binary, directory, unknown=profile == "unknown")
        if profile == "unknown":
            assert len(queries(directory)) == 1
            effects = docker(
                "exec",
                repository,
                "python",
                "-c",
                "from pathlib import Path; print(Path('effects.txt').exists())",
            )
            assert effects.strip() == "False"
            receipts = [exported["unknown_receipt"]]
            evidence = {
                "provider_dispatches": 1,
                "command_effects": 0,
                "unknown_outcome_stopped": True,
                "attempts": expected_attempts,
            }
        else:
            assert exported["result"]["exit_status"] == "Submitted"
            assert exported["model_calls"] == len(queries(directory)) == 3
            assert exported["model_cost"] == 3.0
            assert (
                docker("exec", repository, "cat", "/workspace/effects.txt")
                == "patched\naudit\naudit\n"
            )
            after = docker("exec", repository, "cat", "/workspace/test-output.txt")
            assert "Ran 2 tests" in after and "\nOK\n" in after
            (directory / "tests-after.txt").write_text(after)
            receipts = exported["model_receipts"] + exported["command_receipts"]
            assert len(receipts) == len(set(receipts)) == 8
            assert len(exported["model_receipts"]) == 3 and len(exported["command_receipts"]) == 5
            if first:
                assert first["receipt_json"] == exported["model_receipts"][0]
                assert not docker("ps", "--all", "--quiet", "--filter", "id=" + old_id).strip()
                patch_log = (directory / "host/run-logs/coder-2.stdout").read_text()
                patch = next(
                    json.loads(line) for line in patch_log.splitlines() if '"event"' in line
                )
                assert patch["receipt_json"] in exported["command_receipts"]
            before = (directory / "queries.jsonl").read_bytes()
            repeated, _ = finish(launch(binary, directory))
            assert repeated["workers"][0]["attempts"] == expected_attempts
            assert (directory / "queries.jsonl").read_bytes() == before
            evidence = {
                "provider_dispatches": 3,
                "patch_effects": 1,
                "audit_effects": 2,
                "original_model_and_command_receipts": 8,
                "attempts": expected_attempts,
                "completed_replay": True,
            }
        (directory / "result.json").write_text(json.dumps(exported, indent=2))
        (directory / "receipts.ndjson").write_text("\n".join(receipts) + "\n")
        verified = json.loads(
            command(
                binary,
                "--json",
                "receipt",
                "verify",
                "--input",
                directory / "receipts.ndjson",
                "--trusted-kernel-pubkey",
                directory / "kernel.pub",
            )
        )
        assert verified["receipts_verified"] == len(receipts)
        evidence["verified_receipts"] = len(receipts)
        return evidence
    finally:
        if host is not None and host.poll() is None:
            host.kill()
            host.communicate(timeout=15)
        if gateway_fd is not None:
            try:
                kill_gateway(gateway_fd)
            except ProcessLookupError:
                pass
            os.close(gateway_fd)
        path = directory / "host/runner.db"
        if path.exists():
            with sqlite3.connect(path) as db:
                if db.execute("SELECT 1 FROM sqlite_master WHERE name='run_containers'").fetchone():
                    for (identifier,) in db.execute("SELECT container_id FROM run_containers"):
                        if identifier:
                            subprocess.run(
                                [*DOCKER, "rm", "--force", "--volumes", identifier],
                                capture_output=True,
                                timeout=30,
                            )
        docker("rm", "--force", "--volumes", repository)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--worker-image-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    os.environ["CHIO_MODEL_QUALIFICATION_SECRET"] = "operator-only-fixture-value"
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix="chio-native-mini-"))
    image = json.loads(args.worker_image_file.read_text())
    binary = args.chio.resolve(strict=True)
    result = {
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "worker_image": image["image"],
        "private_state": str(root),
        "provider": "saved tool-call fixture through Chio model gateway",
    }
    print("Private native mini-SWE state: " + str(root), file=sys.stderr, flush=True)
    for profile in ("baseline", "known", "unknown"):
        print(f"Starting native mini-SWE profile: {profile}", file=sys.stderr, flush=True)
        result[profile] = exercise(binary, root / profile, image["base"], image["image"], profile)
        print(f"Passed native mini-SWE profile: {profile}", file=sys.stderr, flush=True)
        target = args.output / profile
        target.mkdir()
        for name in (
            "result.json",
            "receipts.ndjson",
            "kernel.pub",
            "queries.jsonl",
            "run-report.json",
        ):
            shutil.copyfile(root / profile / name, target / name)
    (args.output / "qualification.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()

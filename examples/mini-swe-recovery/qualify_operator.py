"""Installed operator commands, real local HTTP inference and offline result export."""

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

from broker_campaign import BrokerCampaign, provider_endpoint
from qualify import command

from chio_mini_swe.provider_config import SCHEMA, identity
from chio_mini_swe.repository_store import configuration_digest

HERE = Path(__file__).resolve().parent
DOCKER = ["/usr/bin/docker", "--host", "unix:///var/run/docker.sock"]


def failure_classes(text):
    if isinstance(text, bytes):
        text = text[:65536].decode("utf-8", errors="replace")
    text = (text or "")[:65536].lower()
    known = {
        "invalid_model_result": "invalid model result",
        "model_gateway_failed": "model gateway failed",
        "provider_outcome_unknown": "unknown or incomplete provider outcome",
        "provider_regeneration_refused": "automatic regeneration is refused",
        "execution_outcome_unknown": "unknown or incomplete outcome",
        "execution_failed": "mcp execution failed",
        "repository_stopped": "repository execution stopped",
        "provider_configuration_changed": "provider configuration changed",
        "request_timeout": "timed out",
        "output_ceiling": "output_ceiling",
        "permission_denied": "permission denied",
        "connection_refused": "connection refused",
    }
    return sorted(name for name, phrase in known.items() if phrase in text)


def safe_run_report(text):
    if not isinstance(text, (str, bytes)) or len(text) > 65536:
        return None
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(value, dict) or value.get("schema") != "chio.process.run-report.v1":
        return None
    report = {"schema": "chio.process.run-report.v1", "workers": []}
    if type(value.get("complete")) is bool:
        report["complete"] = value["complete"]
    pending = value.get("pending_container_records")
    if type(pending) is int and 0 <= pending <= 128:
        report["pending_container_records"] = pending
    workers = value.get("workers")
    if not isinstance(workers, list) or len(workers) > 2:
        return report
    for row in workers:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("process"), str)
            or row["process"] not in {"root", "coder"}
        ):
            continue
        worker = {"process": row["process"]}
        if isinstance(row.get("state"), str) and row["state"] in {
            "pending",
            "running",
            "completed",
            "failed",
        }:
            worker["state"] = row["state"]
        for field in ("attempts", "suspensions", "peak_resident_bytes", "cpu_ms"):
            number = row.get(field)
            if type(number) is int and 0 <= number <= 2**64 - 1:
                worker[field] = number
        outcome = row.get("outcome")
        if isinstance(outcome, str) and (
            re.fullmatch(r"exit_(?:-1|[0-9]{1,3})", outcome)
            or outcome
            in {
                "timeout",
                "output_ceiling",
                "host_interrupted",
                "runner_interrupted",
                "process_cancelled",
                "container_attachment_lost",
                "container_oom",
                "suspended",
            }
        ):
            worker["outcome"] = outcome
        report["workers"].append(worker)
    return report


def save_failure_diagnostics(root, output, failure):
    # Only fixed classifications and validated report fields leave private state.
    # Worker streams can contain credentials even when native redaction fails.
    diagnostic = {
        "schema": "chio.mini-swe.qualification-failure.v1",
        "stage": "first_operator_run",
        "timed_out": isinstance(failure, subprocess.TimeoutExpired),
        "run_report": safe_run_report(failure.stdout),
        "host_failure_classes": failure_classes(failure.stderr),
        "worker_logs": [],
    }
    if isinstance(failure, subprocess.CalledProcessError):
        diagnostic["returncode"] = failure.returncode
    for attempt in (1, 2):
        for stream in ("stdout", "stderr"):
            record = {"process": "coder", "attempt": attempt, "stream": stream}
            try:
                descriptor = os.open(
                    root / "run/host/run-logs" / f"coder-{attempt}.{stream}",
                    os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                )
                with os.fdopen(descriptor, "rb") as incoming:
                    if not stat.S_ISREG(os.fstat(incoming.fileno()).st_mode):
                        raise ValueError("Not a regular log")
                    data = incoming.read(65537)
                record.update(
                    available=True, truncated=len(data) > 65536, classes=failure_classes(data)
                )
            except (OSError, ValueError):
                record["available"] = False
            diagnostic["worker_logs"].append(record)
    (output / "operator-failure.json").write_text(json.dumps(diagnostic, indent=2) + "\n")


def cleanup_workers(root):
    for name in ("run", "failed"):
        path = root / name / "host/runner.db"
        if not path.exists():
            continue
        with sqlite3.connect(path) as db:
            if not db.execute("SELECT 1 FROM sqlite_master WHERE name='run_containers'").fetchone():
                continue
            for owner, identifier in db.execute("SELECT owner, container_id FROM run_containers"):
                if not identifier:
                    continue
                observed = subprocess.run(
                    [*DOCKER, "inspect", identifier], capture_output=True, text=True, timeout=30
                )
                if observed.returncode:
                    continue
                record = json.loads(observed.stdout)[0]
                assert (
                    record["Id"] == identifier
                    and record["Config"]["Labels"]["chio.runner.owner"] == owner
                )
                command(*DOCKER, "rm", "--force", "--volumes", identifier)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--worker-image-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repository-service", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    os.environ["CHIO_OPERATOR_FIXTURE_KEY"] = "local-http-fixture-value"
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix="chio-coding-"))
    source_binary = args.chio.resolve(strict=True)
    binary = root / "chio"
    shutil.copyfile(source_binary, binary)
    binary.chmod(0o700)
    assert (
        hashlib.sha256(binary.read_bytes()).digest()
        == hashlib.sha256(source_binary.read_bytes()).digest()
    )
    operator = Path(sys.executable).parent / "chio-mini-swe"
    image = json.loads(args.worker_image_file.read_text())
    services = None
    failed_services = None

    def calls():
        return (
            [json.loads(line) for line in (root / "queries.jsonl").read_text().splitlines()]
            if (root / "queries.jsonl").exists()
            else []
        )

    repository = None
    workspace_fixture = None
    print("Private operator qualification state: " + str(root), file=sys.stderr, flush=True)
    try:
        if args.repository_service:
            from qualify_repository import RepositoryFixture

            workspace_fixture = RepositoryFixture(root, image, timeout=90)
        else:
            repository = command(
                *DOCKER,
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
                image["base"],
                "sleep",
                "1800",
            ).strip()
        if repository is not None:
            command(
                *DOCKER,
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
        provider = {
            "schema": SCHEMA,
            "endpoint": provider_endpoint(),
            "allow_loopback_http": False,
            "model": "local-coding-fixture",
            "credential_env": "CHIO_OPERATOR_FIXTURE_KEY",
            "max_output_tokens": 1024,
            "timeout_seconds": 10,
            "input_usd_per_million": 2,
            "output_usd_per_million": 8,
        }
        (root / "provider.json").write_text(json.dumps(provider))
        services = BrokerCampaign(
            binary,
            root,
            repository,
            "operator",
            provider=provider,
            host_state=root / "run/host",
            workspace=workspace_fixture.state if workspace_fixture else None,
            slow_command=bool(workspace_fixture),
        )
        host = json.loads((root / "config.json").read_text())
        (root / "host.json").write_text(json.dumps(host))
        profile = {
            "schema": "chio.mini-swe.operator.v1",
            "chio": str(binary),
            "host_config": "host.json",
            "provider_config": "provider.json",
            "process": "coder",
            "worker_image": image["image"],
            "model_server": "model",
            "execution": {"server_id": "sandbox", "tool_name": "execute"},
            "environment": {
                "cwd": "/workspace",
                **(
                    {
                        "repository_configuration_sha256": configuration_digest(
                            json.loads((workspace_fixture.state / "workspace.json").read_text())
                        )
                    }
                    if workspace_fixture
                    else {}
                ),
            },
            "agent": {
                "system_template": "Repair the Python repository using bash commands.",
                "instance_template": "{{task}}",
                "step_limit": 8,
                "cost_limit": 1,
                "wall_time_limit_seconds": 600,
            },
            "max_attempts": 2,
            "timeout_seconds": 300 if workspace_fixture else 90,
        }
        (root / "profile.json").write_text(json.dumps(profile))
        (root / "task.md").write_text("Fix addition and verify the existing unit tests.")
        prepared = json.loads(
            command(
                operator,
                "prepare",
                "--profile",
                root / "profile.json",
                "--task-file",
                root / "task.md",
                "--state",
                root / "run",
                cwd=root,
            )
        )
        assert prepared["model_id"] == identity(provider) and not calls()
        changed = dict(provider, model="different-model")
        (root / "provider.json").write_text(json.dumps(changed))
        rejected = subprocess.run(
            [str(operator), "run", "--state", str(root / "run")],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=root,
        )
        assert (
            rejected.returncode
            and "Provider configuration changed" in rejected.stderr
            and not calls()
        )
        (root / "provider.json").write_text(json.dumps(provider))
        services.start(binary)
        try:
            report = json.loads(
                subprocess.run(
                    [str(operator), "run", "--state", str(root / "run")],
                    cwd=root,
                    text=True,
                    capture_output=True,
                    check=True,
                    timeout=profile["max_attempts"] * profile["timeout_seconds"] + 60,
                ).stdout
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as failure:
            save_failure_diagnostics(root, args.output, failure)
            raise
        assert report["complete"] and report["workers"][0]["attempts"] == 1 and len(calls()) == 3

        if workspace_fixture:
            services.release_repository()

        def repository_file(name):
            if workspace_fixture:
                return workspace_fixture.read(name)
            return command(*DOCKER, "exec", repository, "cat", "/workspace/" + name)

        assert repository_file("effects.txt") == "patched\naudit\naudit\n"
        assert "\nOK\n" in repository_file("test-output.txt")
        again = json.loads(command(operator, "run", "--state", root / "run", cwd=root))
        assert again == report and len(calls()) == 3
        command(binary, "process", "cancel", "--state", root / "run/host", "--process", "coder")
        # Starting this model server would now fail. Administrative result export
        # must still work, including after cancellation and without a credential.
        (root / "provider.json").rename(root / "provider-disabled.json")
        tracked = [
            p for p in (root / "run/host").rglob("*") if p.is_file() and not p.name.endswith("-shm")
        ]
        before = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked}
        exported = json.loads(
            command(operator, "result", "--state", root / "run", "--out", root / "result", cwd=root)
        )
        after = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in tracked}
        assert before == after and exported["verified_receipts"] == 8 and len(calls()) == 3
        assert exported["exit_status"] == "Submitted"
        assert abs(exported["model_cost"] - 0.00108) < 1e-12
        (root / "provider-disabled.json").rename(root / "provider.json")
        failure_root = root / "failure-services"
        failure_root.mkdir(mode=0o700)
        failure_provider = dict(provider, endpoint=provider_endpoint())
        (root / "failure-provider.json").write_text(json.dumps(failure_provider))
        failed_services = BrokerCampaign(
            binary,
            failure_root,
            repository,
            "operator-error",
            provider=failure_provider,
            host_state=root / "failed/host",
            workspace=workspace_fixture.state if workspace_fixture else None,
        )
        failed_services.failed.set()
        failed_host = json.loads((failure_root / "config.json").read_text())
        (root / "failed-host.json").write_text(json.dumps(failed_host))
        failed_profile = dict(
            profile, host_config="failed-host.json", provider_config="failure-provider.json"
        )
        (root / "failed-profile.json").write_text(json.dumps(failed_profile))
        command(
            operator,
            "prepare",
            "--profile",
            root / "failed-profile.json",
            "--task-file",
            root / "task.md",
            "--state",
            root / "failed",
            cwd=root,
        )
        failed_services.start(binary)
        stopped = subprocess.run(
            [str(operator), "run", "--state", str(root / "failed")],
            capture_output=True,
            text=True,
            timeout=180,
            cwd=root,
        )
        failure_calls = [
            json.loads(line) for line in (failure_root / "queries.jsonl").read_text().splitlines()
        ]
        assert stopped.returncode and len(calls()) == 3 and len(failure_calls) == 1
        failed_services.close()
        failed_services = None
        stop_report = json.loads(stopped.stdout)
        assert not stop_report["complete"] and stop_report["workers"][0]["attempts"] == 2
        assert repository_file("effects.txt") == "patched\naudit\naudit\n"
        evidence = {
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "worker_image": image["image"],
            "private_state": str(root),
            "provider": "saved HTTPS completions through native prepared broker routes",
            "model_id": prepared["model_id"],
            "successful_http_requests": 3,
            "failed_http_requests": 1,
            "failure_attempts": 2,
            "command_exceeds_default_client_and_host_timeout": bool(workspace_fixture),
            "verified_receipts": 8,
            "configuration_change_refused": True,
            "completed_replay": True,
            "offline_cancelled_export_without_host_writes": True,
            "provider_error_stopped": True,
        }
        if workspace_fixture:
            evidence["repository"] = workspace_fixture.verify(args.output / "repository")
        for path in (root / "result").iterdir():
            shutil.copyfile(path, args.output / path.name)
        (args.output / "qualification.json").write_text(json.dumps(evidence, indent=2) + "\n")
        (args.output / "http-requests.json").write_text(
            json.dumps(calls() + failure_calls, indent=2) + "\n"
        )
        print(json.dumps(evidence))
    finally:
        if failed_services is not None:
            failed_services.close()
        if services is not None:
            services.close()
        cleanup_workers(root)
        if repository is not None:
            command(*DOCKER, "rm", "--force", "--volumes", repository)
        if workspace_fixture:
            workspace_fixture.cleanup()


if __name__ == "__main__":
    main()

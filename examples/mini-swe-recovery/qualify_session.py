"""Installed two-stage coding session with explicit fixture-only launch authority."""

import argparse
import fcntl
import hashlib
import http.server
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from chio_mini_swe.repository_archive import git
from chio_mini_swe.repository_transport import docker
from chio_process.launch import provision_native_demo

DIAGNOSTICS = None


def command(*arguments, expected=0, timeout=180):
    result = subprocess.run(
        [str(argument) for argument in arguments],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if (result.returncode == 0) != (expected == 0):
        if DIAGNOSTICS is not None:
            # Retain failures only in the private task directory. These streams
            # are never copied to the shareable qualification evidence.
            (DIAGNOSTICS / "command-failure.stdout").write_text(result.stdout[:65536])
            (DIAGNOSTICS / "command-failure.stderr").write_text(result.stderr[:65536])
        raise RuntimeError(
            f"{Path(str(arguments[0])).name} returned unexpected status {result.returncode}"
        )
    return json.loads(result.stdout) if expected == 0 else result.returncode


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + "\n")


def main():
    global DIAGNOSTICS
    parser = argparse.ArgumentParser(description="Qualify the installed coding session workflow")
    parser.add_argument("--chio", type=Path, required=True)
    parser.add_argument("--worker-image-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--scoped", action="store_true", help="Select one committed package directory"
    )
    args = parser.parse_args()
    os.umask(0o077)
    args.output.mkdir(parents=True, exist_ok=False)
    root = Path(tempfile.mkdtemp(prefix="chio-session-"))
    DIAGNOSTICS = root
    os.environ["MSWEA_GLOBAL_CONFIG_DIR"] = str(root / "mini-config")
    os.environ["MSWEA_SILENT_STARTUP"] = "1"
    from worker import decisions

    print("Private session qualification state: " + str(root), file=sys.stderr, flush=True)
    binary = args.chio.resolve(strict=True)
    operator = Path(sys.executable).parent / "chio-mini-swe"
    reviewer = Path(sys.executable).parent / "chio-mini-swe-repository"
    image = json.loads(args.worker_image_file.read_text())
    source = root / "source"
    source.mkdir()
    git("init", "--quiet", cwd=source)
    project = source / "package" if args.scoped else source
    if args.scoped:
        project.mkdir()
        (source / "unselected.txt").write_text("Unselected committed fixture content\n")
    (project / "calculator.py").write_text("def add(a, b):\n    return a - b\n")
    (project / "test_calculator.py").write_text(
        "import unittest\nfrom calculator import add\n"
        "class Addition(unittest.TestCase):\n"
        "    def test_positive(self):\n        self.assertEqual(add(2, 3), 5)\n"
        "    def test_negative(self):\n        self.assertEqual(add(-2, -3), -5)\n"
    )
    git("add", "--all", cwd=source)
    git(
        "-c",
        "user.name=Fixture",
        "-c",
        "user.email=fixture@localhost",
        "commit",
        "--quiet",
        "-m",
        "session fixture",
        cwd=source,
    )
    revision = git("rev-parse", "HEAD", cwd=source).decode().strip()
    (project / "calculator.py").write_text("private dirty reviewer file\n")
    (source / "private-untracked").write_text("untracked fixture data\n")

    def source_hashes():
        return {
            str(p.relative_to(source)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in source.rglob("*")
            if p.is_file() and ".git" not in p.relative_to(source).parts
        }

    source_before = source_hashes()
    calls = []
    credential_name = "CHIO_SESSION_FIXTURE_KEY"
    credential = "session-http-fixture-value"
    os.environ.pop(credential_name, None)

    class Provider(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            assert self.path == "/v1/chat/completions"
            assert self.headers["Authorization"] == "Bearer " + credential
            assert credential not in body.decode()
            value = json.loads(body)
            turn = sum(message["role"] == "assistant" for message in value["messages"])
            calls.append({"turn": turn, "request_sha256": hashlib.sha256(body).hexdigest()})
            if turn == 0:
                # This crosses the native host's default 60-second request
                # deadline and proves the session's derived model timeout.
                time.sleep(65)
            message = decisions()[turn]
            message.pop("extra")
            if args.scoped:
                assert any(
                    "Selected paths:" in item.get("content", "") and "package" in item["content"]
                    for item in value["messages"]
                    if item["role"] == "user"
                )
                for call in message["tool_calls"]:
                    action = json.loads(call["function"]["arguments"])
                    action["command"] = (
                        "test ! -e unselected.txt && cd package && " + action["command"]
                    )
                    call["function"]["arguments"] = json.dumps(action)
            response = {
                "id": f"session-{len(calls)}",
                "object": "chat.completion",
                "created": 1,
                "model": "session-fixture",
                "choices": [{"index": 0, "finish_reason": "tool_calls", "message": message}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20, "total_tokens": 120},
            }
            encoded = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    closed = False
    session = root / "session"
    try:
        write(
            root / "provider.json",
            {
                "schema": "chio.mini-swe.provider.v1",
                "endpoint": f"http://127.0.0.1:{server.server_port}/v1",
                "allow_loopback_http": True,
                "model": "session-fixture",
                "credential_env": credential_name,
                "max_output_tokens": 1024,
                "timeout_seconds": 90,
                "input_usd_per_million": 2,
                "output_usd_per_million": 8,
            },
        )
        write(
            root / "config.json",
            {
                "schema": "chio.mini-swe.session-config.v2"
                if args.scoped
                else "chio.mini-swe.session-config.v1",
                **({"source_paths": ["package"]} if args.scoped else {}),
                "chio": str(binary),
                "repository": str(source),
                "revision": revision,
                "provider_config": "provider.json",
                "worker_image": image["image"],
                "execution_image": image["execution_image"],
                "helper_image": docker("image", "inspect", image["base"], "--format", "{{.Id}}")
                .decode()
                .strip(),
                "command_timeout_seconds": 20,
                "agent": {
                    "system_template": "Repair the Python repository using bash commands.",
                    "instance_template": "{{task}} Selected paths: {{source_paths}}"
                    if args.scoped
                    else "{{task}}",
                    "step_limit": 8,
                    "cost_limit": 1,
                    "wall_time_limit_seconds": 600,
                },
                "max_attempts": 2,
                "timeout_seconds": 240,
                "max_calls": 16,
                "capability_ttl_seconds": 3600,
            },
        )
        (root / "task.md").write_text("Fix addition and verify the existing unit tests.")
        initialized = command(
            operator,
            "session",
            "init",
            "--config",
            root / "config.json",
            "--task-file",
            root / "task.md",
            "--state",
            session,
        )
        assert not calls and credential_name not in os.environ
        request = json.loads((session / "provisioning-request.json").read_text())
        assert request["source_commit"] == revision and set(request["servers"]) == {
            "model",
            "sandbox",
        }
        assert credential not in (session / "provisioning-request.json").read_text()
        assert not (session / "run").exists()
        command(operator, "session", "run", "--state", session, expected=1)
        assert not (session / "run").exists() and not calls
        # Authority is deliberately issued by this separate test harness.
        # Production session commands never call this Disabled-stage provisioner.
        bindings = {}
        for name, expected in request["servers"].items():
            configured = provision_native_demo(
                binary,
                name,
                expected["command"],
                root / ("launch-" + name),
                expected["working_directory"],
            )
            bindings[name] = {
                key: configured[key] for key in ("launch_policy", "launch_policy_signer")
            }
        write(
            root / "authorization.json",
            {
                "schema": "chio.mini-swe.session-authorization.v1",
                "servers": bindings,
            },
        )
        prepared = command(
            operator,
            "session",
            "prepare",
            "--state",
            session,
            "--authorization",
            root / "authorization.json",
        )
        assert not calls and credential_name not in os.environ
        host = json.loads((session / "host.json").read_text())
        deadlines = {s["id"]: s["request_timeout_seconds"] for s in host["servers"]}
        assert deadlines == {"model": 120, "sandbox": 140}
        with (session / "run/host/host.lock").open("rb") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            command(operator, "session", "recover", "--state", session, expected=1)
            command(
                operator,
                "session",
                "result",
                "--state",
                session,
                "--out",
                root / "locked-export",
                expected=1,
            )
            assert not (root / "locked-export").exists()
        os.environ[credential_name] = credential
        completed = command(operator, "session", "run", "--state", session, timeout=540)
        assert len(calls) == 3
        repeated = command(operator, "session", "run", "--state", session, timeout=540)
        assert len(calls) == 3
        os.environ.pop(credential_name, None)
        server.shutdown()
        server.server_close()
        thread.join(timeout=10)
        closed = True
        # Removing original inputs must not affect the prepared session snapshot.
        (root / "provider.json").unlink()
        (root / "task.md").unlink()
        observed = command(operator, "session", "status", "--state", session)
        exported = command(
            operator, "session", "result", "--state", session, "--out", root / "result"
        )
        bundle = root / "result/repository"
        review = command(
            reviewer,
            "verify-export",
            "--bundle",
            bundle,
            "--repository",
            source,
            "--revision",
            revision,
            "--chio",
            binary,
            "--kernel-key",
            root / "result/operator/kernel.pub",
            "--server-id",
            "sandbox",
            *(["--source-path", "package"] if args.scoped else []),
        )
        assert review["verified_transitions"] == 5
        assert review["verification"]["receipts_verified"] == 8
        assert source_before == source_hashes()
        if args.scoped:
            assert (
                review["source_paths"]
                == observed["source_paths"]
                == exported["source_paths"]
                == ["package"]
            )
        command(operator, "session", "recover", "--state", session)
        assert len(calls) == 3
        record = {
            "schema": "chio.mini-swe.session-qualification.v1",
            "private_state": str(root),
            "initialized": initialized,
            "prepared": prepared,
            "completed": completed,
            "repeated": repeated,
            "observed": observed,
            "exported": exported,
            "review": review,
            "model_requests": calls,
            "request_timeouts": deadlines,
            "slow_model_crossed_default_deadline": True,
            "prepare_without_provider_credential_or_inference": True,
            "separate_explicit_fixture_authority": True,
            "held_native_host_lock_refused_recovery_and_export": True,
            "completed_replay_did_no_new_model_work": True,
            "offline_combined_export": True,
            "source_unchanged": True,
            "source_paths": ["package"] if args.scoped else None,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "image_record": image,
        }
        write(args.output / "qualification.json", record)
        shutil.copytree(root / "result", args.output / "result")
        print(json.dumps({"output": str(args.output), "verified_transitions": 5, "model_calls": 3}))
    finally:
        os.environ.pop(credential_name, None)
        if not closed:
            server.shutdown()
            server.server_close()
            thread.join(timeout=10)


if __name__ == "__main__":
    main()

"""A durable stop reached through the control socket and the offline CLI."""

import json
import select
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from chio_process import ProcessClient

BINARY = sys.argv[1]


def cli(*args, success=True):
    result = subprocess.run(
        [BINARY, "process", *map(str, args)],
        capture_output=True,
        text=True,
        timeout=90,
        check=False,
    )
    assert (result.returncode == 0) == success, (args, result.stdout, result.stderr)
    return json.loads(result.stdout)


def serve(state, socket):
    host = subprocess.Popen(
        [BINARY, "process", "serve", "--state", str(state), "--socket", str(socket)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert select.select([host.stdout], [], [], 90)[0], "host startup timed out"
    line = host.stdout.readline()
    assert line, host.stderr.read()
    ready = json.loads(line)
    assert ready["ready"], ready
    return host, ready


def shut_down(host):
    if host.poll() is None:
        host.send_signal(signal.SIGTERM)
    try:
        host.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        host.kill()
        host.communicate(timeout=10)
        raise


def denied(client, key):
    try:
        response = client.invoke(key, "chio-ipc", "send_jobs", {"message_key": key, "payload": {}})
    except Exception:  # noqa: BLE001 - a refused call may surface as a worker error
        return True
    return response["verdict"] == "deny"


def exercise(directory):
    state = directory / "state"
    socket = directory / "host.sock"
    policy = directory / "policy.yaml"
    policy.write_text("""kernel:
  max_capability_ttl: 3600
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: chio-ipc
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
""")
    source = directory / "config.json"
    source.write_text(
        json.dumps(
            {
                "schema": "chio.process.host.v1",
                "policy": str(policy),
                "mailboxes": [{"id": "jobs"}],
                "limits": {"max_processes": 1, "max_depth": 0, "max_calls": 20},
            }
        )
    )
    cli("init", "--config", source, "--state", state)
    descriptor = directory / "connection.json"
    cli(
        "credential", "--state", state, "--process", "root", "--socket", socket, "--out", descriptor
    )
    connection = json.loads(descriptor.read_text())

    host, ready = serve(state, socket)
    try:
        assert ready["stop"]["readiness"] == {"state": "ready"}, ready
        client = ProcessClient(connection["socket_path"], connection["credential"])
        assert not denied(client, "before-stop")
        stopped = cli("stop", "--state", state, "--reason", "incident drill")
        assert stopped["via"] == "control_socket", stopped
        status = stopped["response"]["status"]
        assert status["durability"] == "durable" and status["stopped"], stopped
        assert status["head"]["epoch"] == 1, stopped
        assert denied(client, "while-stopped")
        token = state / "control.token"
        original = token.read_text()
        token.write_text("0" * len(original))
        refused = cli("stop-status", "--state", state, success=False)
        assert refused["response"]["error"] == "unauthorized", refused
        token.write_text(original)
    finally:
        shut_down(host)

    host, ready = serve(state, socket)
    try:
        assert ready["stop"]["readiness"] == {"state": "ready_stopped"}, ready
        client = ProcessClient(connection["socket_path"], connection["credential"])
        assert denied(client, "after-restart")
        status = cli("stop-status", "--state", state)
        assert status["via"] == "control_socket", status
        assert status["response"]["status"]["head"]["epoch"] == 1, status
    finally:
        shut_down(host)

    offline = cli("stop-status", "--state", state)
    assert offline["via"] == "offline" and offline["response"]["status"]["stopped"], offline
    moved = cli("resume", "--state", state, "--expected-epoch", "7", success=False)
    assert moved["response"]["error"] == "stop_head_moved", moved
    resumed = cli("resume", "--state", state, "--expected-epoch", "1")
    assert resumed["via"] == "offline", resumed
    assert not resumed["response"]["status"]["stopped"], resumed

    host, ready = serve(state, socket)
    try:
        assert ready["stop"]["readiness"] == {"state": "ready"}, ready
        client = ProcessClient(connection["socket_path"], connection["credential"])
        assert not denied(client, "after-resume")
    finally:
        shut_down(host)


with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary) / "case"
    root.mkdir(mode=0o700)
    exercise(root)

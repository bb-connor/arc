"""REST-1 TEST-03 for the non-recovery native lifecycle: host OS death at dispatch cutpoints.

Each case kills `chio process serve` with SIGKILL while the caged report fixture
holds an append before (C1) or after (C2) its effect, with the authority WAL
uncheckpointed (C5). C4 also kills the restarted host three times during
startup. The restarted host must answer the same request identity with one
signed unknown-outcome denial, never redispatch, refuse the revoked pre-crash
credential, keep the consumed call and still serve fresh calls up to the shared
ceiling.
"""

import json
import select
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from chio_process import ProcessClient, WorkerError
from recovery import report_server

MAX_CALLS = 4
UNKNOWN = "dispatch outcome is unknown after recovery"
POLICY = """kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 2
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: reports
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
"""


def cli(binary, *arguments, success=True):
    result = subprocess.run(
        [binary, "process", *map(str, arguments)],
        text=True,
        capture_output=True,
        timeout=90,
        check=False,
    )
    assert (result.returncode == 0) == success, (arguments, result.stdout, result.stderr)
    return json.loads(result.stdout) if success else result.stderr


class Host:
    def __init__(self, binary, directory):
        self.binary = binary
        self.directory = directory
        directory.mkdir(mode=0o700)
        (directory / "tool-data").mkdir()
        for name in ("sockets", "descriptors"):
            (directory / name).mkdir(mode=0o700)
        self.state = directory / "state"
        self.publications = directory / "tool-data" / "publications.jsonl"
        (directory / "policy.yaml").write_text(POLICY)
        config = {
            "schema": "chio.process.host.v1",
            "policy": "policy.yaml",
            "servers": [report_server(binary, directory)],
            "limits": {"max_calls": MAX_CALLS, "max_processes": 2, "max_depth": 1},
            "children": [
                {
                    "id": "agent",
                    "parent": "root",
                    "tools": [
                        {"server_id": "reports", "tool_name": "read"},
                        {"server_id": "reports", "tool_name": "append"},
                    ],
                    "budget_share_bps": 5000,
                }
            ],
        }
        path = directory / "host-config.json"
        path.write_text(json.dumps(config))
        self.kernel_key = cli(binary, "init", "--config", path, "--state", self.state)["kernel_key"]

    def socket(self, name):
        return self.directory / "sockets" / f"{name}.sock"

    def credential(self, socket):
        out = self.directory / "descriptors" / f"{socket.stem}.json"
        cli(
            self.binary,
            "credential",
            "--state",
            self.state,
            "--process",
            "agent",
            "--socket",
            socket,
            "--out",
            out,
        )
        descriptor = json.loads(out.read_text())
        return descriptor["credential"], ProcessClient(
            descriptor["socket_path"], descriptor["credential"]
        )

    def start(self, socket):
        return subprocess.Popen(
            [self.binary, "process", "serve", "--state", str(self.state), "--socket", str(socket)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def ready(self, host):
        assert select.select([host.stdout], [], [], 90)[0], "host startup timed out"
        line = host.stdout.readline()
        assert line, host.stderr.read()
        ready = json.loads(line)
        assert ready["ready"], ready
        assert ready["kernel_key"] == self.kernel_key
        return host

    def stop(self, host):
        host.send_signal(signal.SIGTERM)
        host.communicate(timeout=30)

    def lines(self):
        return len(self.publications.read_text().splitlines())


def kill(host):
    host.kill()
    host.communicate(timeout=15)


def wait_for_hold(held, host):
    deadline = time.monotonic() + 90
    while held.stat().st_size == 0:
        assert host.poll() is None, host.communicate()
        assert time.monotonic() < deadline, "fixture never reached its hold"
        time.sleep(0.05)


def crash_during_startup(node):
    """Kill restarted hosts before any output, after ready, and after one inspect."""
    early = node.start(node.socket("startup-early"))
    kill(early)
    kill(node.ready(node.start(node.socket("startup-ready"))))
    socket = node.socket("startup-inspect")
    _, client = node.credential(socket)
    host = node.ready(node.start(socket))
    assert client.inspect()["process_id"] == "agent"
    kill(host)


def case(binary, root, cutpoint, hold, effects, startup_crashes):
    node = Host(binary, root / cutpoint)
    control = node.publications.with_suffix(".control")
    held = node.publications.with_suffix(".held")
    control.write_text(hold)
    first = node.socket("first")
    old_credential, client = node.credential(first)
    host = node.ready(node.start(first))
    outcome = {}

    def held_call():
        try:
            outcome["result"] = client.invoke(
                "cut-append", "reports", "append", {"report": cutpoint}
            )
        except (WorkerError, OSError, ValueError) as failure:
            outcome["failure"] = failure

    caller = threading.Thread(target=held_call)
    caller.start()
    wait_for_hold(held, host)
    kill(host)
    caller.join(timeout=60)
    assert not caller.is_alive(), "caller survived host death"
    assert "result" not in outcome, outcome
    assert first.exists(), "OS death must leave the old socket entry"
    wal = node.state / "authority.db-wal"
    assert wal.exists() and wal.stat().st_size > 0, "WAL was checkpointed before death"
    assert node.lines() == effects
    if startup_crashes:
        crash_during_startup(node)

    cli(binary, "revoke", "--state", node.state, "--process", "agent")
    recovered = node.socket("recovered")
    credential, client = node.credential(recovered)
    assert credential != old_credential
    host = node.ready(node.start(recovered))
    try:
        try:
            ProcessClient(str(recovered), old_credential).inspect()
            raise AssertionError("revoked pre-crash credential accepted")
        except WorkerError as failure:
            assert failure.code == "unauthenticated", failure
        retried = client.invoke("cut-append", "reports", "append", {"report": cutpoint})
        assert retried["verdict"] == "deny", retried
        assert retried["output"] is None, retried
        assert retried["reason"] == UNKNOWN, retried
        again = client.invoke("cut-append", "reports", "append", {"report": cutpoint})
        assert again["receipt_json"] == retried["receipt_json"]
        assert node.lines() == effects
        control.write_text("ready")
        released = client.invoke("cut-append", "reports", "append", {"report": cutpoint})
        assert released["receipt_json"] == retried["receipt_json"]
        assert node.lines() == effects, "unknown outcome was redispatched"
        for index in range(MAX_CALLS - 1):
            read = client.invoke(f"read-{index}", "reports", "read", {"path": "source.txt"})
            assert read["verdict"] == "allow", read
        try:
            client.invoke("over-ceiling", "reports", "read", {"path": "source.txt"})
            raise AssertionError("consumed call was replenished by the restart")
        except WorkerError as failure:
            assert failure.code == "limit_reached", failure
    finally:
        node.stop(host)
    assert node.lines() == effects
    return {
        "cutpoint": cutpoint,
        "receipt_json": retried["receipt_json"],
        "kernel_key": node.kernel_key,
        "publications": node.lines(),
    }


def exercise(binary, root):
    return {
        "cases": [
            case(binary, root, "C1", "hold-before", 0, startup_crashes=False),
            case(binary, root, "C2", "hold-after", 1, startup_crashes=False),
            case(binary, root, "C4", "hold-after", 1, startup_crashes=True),
        ]
    }


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="chio-process-os-death-") as temporary:
        print(json.dumps(exercise(sys.argv[1], Path(temporary))))

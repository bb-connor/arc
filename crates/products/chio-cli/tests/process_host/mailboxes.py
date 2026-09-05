"""Native mailbox-only host configuration and the public worker interface."""

import json
import select
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from chio_process import ProcessClient


def exercise(binary, directory):
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
    config = {
        "schema": "chio.process.host.v1",
        "policy": str(policy),
        "mailboxes": [{"id": "jobs"}],
        "limits": {"max_processes": 1, "max_depth": 0, "max_calls": 10},
    }
    source = directory / "config.json"
    source.write_text(json.dumps(config))

    def cli(*args, success=True):
        result = subprocess.run(
            [binary, "process", *map(str, args)],
            capture_output=True,
            text=True,
            timeout=90,
        )
        assert (result.returncode == 0) == success, (args, result.stderr)
        return json.loads(result.stdout) if success else result.stderr

    cli("init", "--config", source, "--state", state)
    descriptor = directory / "connection.json"
    cli(
        "credential",
        "--state",
        state,
        "--process",
        "root",
        "--socket",
        socket,
        "--out",
        descriptor,
    )
    connection = json.loads(descriptor.read_text())
    assert [tool["tool_name"] for tool in connection["tools"]] == [
        "ack_jobs",
        "receive_jobs",
        "send_jobs",
    ]
    host = subprocess.Popen(
        [binary, "process", "serve", "--state", str(state), "--socket", str(socket)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert select.select([host.stdout], [], [], 90)[0], "host startup timed out"
        line = host.stdout.readline()
        assert line, host.stderr.read()
        assert json.loads(line)["ready"]
        client = ProcessClient(connection["socket_path"], connection["credential"])
        for key, tool, args, expected in [
            (
                "send",
                "send_jobs",
                {"message_key": "job", "payload": {"text": "ready"}},
                {"status": "sent", "sequence": "1"},
            ),
            (
                "receive",
                "receive_jobs",
                {"after_sequence": "0", "limit": 1},
                {
                    "status": "received",
                    "messages": [{"sequence": "1", "payload": {"text": "ready"}}],
                    "next_sequence": "1",
                },
            ),
            (
                "ack",
                "ack_jobs",
                {"through_sequence": "1"},
                {"status": "acknowledged", "through_sequence": "1"},
            ),
        ]:
            response = client.invoke(key, "chio-ipc", tool, args)
            assert response["verdict"] == "allow", response
            assert response["output"]["value"] == expected, response
    finally:
        if host.poll() is None:
            host.send_signal(signal.SIGTERM)
        try:
            host.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            host.kill()
            host.communicate(timeout=10)
            raise
    for number, change in enumerate(
        [
            {"mailboxes": [{"id": "jobs"}, {"id": "jobs"}]},
            {"mailboxes": [{"id": "path/escape"}]},
            {
                "mailboxes": [
                    {
                        "id": "jobs",
                        "limits": {
                            "max_pending_messages": 0,
                            "max_pending_bytes": 128,
                            "max_message_bytes": 128,
                            "max_messages": 1,
                        },
                    }
                ]
            },
            {"servers": [{"id": "chio-ipc", "command": ["/must/not/launch"]}]},
            {"mailboxes": []},
        ]
    ):
        source.write_text(json.dumps({**config, **change}))
        cli(
            "init",
            "--config",
            source,
            "--state",
            directory / f"invalid-{number}",
            success=False,
        )


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="chio-native-") as temporary:
        exercise(sys.argv[1], Path(temporary))

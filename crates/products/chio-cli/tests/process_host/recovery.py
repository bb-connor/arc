"""Real CLI, MCP subprocess, Python client, and persistent host recovery."""

import contextlib
import json
import os
import select
import signal
import subprocess
import sys
import tempfile
from pathlib import Path


def mcp(publications):
    for line in sys.stdin:
        message = json.loads(line)
        if "id" not in message:
            continue
        method = message["method"]
        if method == "initialize":
            result = {
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "report-tools", "version": "1"},
            }
        elif method == "tools/list":
            suffix = "changed" if publications.with_suffix(".changed").exists() else ""
            result = {
                "tools": [
                    {
                        "name": name + suffix,
                        "description": "Report tool",
                        "inputSchema": {"type": "object"},
                    }
                    for name in ["read", "append"]
                ]
            }
        elif method == "tools/call":
            if message["params"]["name"] == "append":
                with publications.open("a") as output:
                    output.write(json.dumps(message["params"]["arguments"]) + "\n")
                    output.flush()
                    os.fsync(output.fileno())
                if publications.with_suffix(".pause").exists():
                    # Failure oracle: hold the effect without returning an outcome.
                    # Host death closes stdin, allowing this test tool to exit.
                    sys.stdin.readline()
                    return
                value = {"published": True}
            else:
                assert message["params"]["arguments"]["path"] == "source.txt"
                value = {"source": publications.with_suffix(".source.txt").read_text()}
            result = {
                "content": [{"type": "text", "text": json.dumps(value)}],
                "structuredContent": value,
            }
        else:
            raise AssertionError(method)
        print(
            json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}),
            flush=True,
        )


def exercise(binary, directory):
    from chio_process import ProcessClient, WorkerError

    state = directory / "state"
    sockets = directory / "sockets"
    sockets.mkdir(mode=0o700)
    descriptors = directory / "descriptors"
    descriptors.mkdir(mode=0o700)
    publications = directory / "publications.jsonl"
    publications.with_suffix(".source.txt").write_text("A useful report source.")
    policy = directory / "policy.yaml"
    original_policy = """kernel:
  max_capability_ttl: 3600
  delegation_depth_limit: 8
  durable_admission_mode: all
capabilities:
  default:
    tools:
      - server: reports
        tool: '*'
        operations: [invoke, delegate]
        ttl: 3600
"""
    policy.write_text(original_policy)

    def route(tool):
        return {"server_id": "reports", "tool_name": tool}

    config = {
        "schema": "chio.process.host.v1",
        "policy": "policy.yaml",
        "servers": [
            {
                "id": "reports",
                "command": [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--mcp",
                    str(publications),
                ],
            }
        ],
        "limits": {"max_calls": 10, "max_processes": 4, "max_depth": 2},
        "children": [
            {
                "id": "reader",
                "parent": "root",
                "tools": [route("read")],
                "budget_share_bps": 3000,
            },
            {
                "id": "writer",
                "parent": "root",
                "tools": [route("read"), route("append")],
                "budget_share_bps": 3000,
            },
            {
                "id": "publisher",
                "parent": "writer",
                "tools": [route("append")],
                "budget_share_bps": 1000,
            },
        ],
    }
    config_path = directory / "host-config.json"
    config_path.write_text(json.dumps(config))

    def cli(*arguments, success=True):
        result = subprocess.run(
            [binary, "process", *map(str, arguments)],
            text=True,
            capture_output=True,
            timeout=90,
        )
        assert (result.returncode == 0) == success, (
            arguments,
            result.stdout,
            result.stderr,
        )
        return json.loads(result.stdout) if success else result.stderr

    def connection(process, filename, socket):
        out = descriptors / filename
        response = cli(
            "credential",
            "--state",
            state,
            "--process",
            process,
            "--socket",
            socket,
            "--out",
            out,
        )
        descriptor = json.loads(out.read_text())
        assert descriptor["credential"] not in json.dumps(response)
        assert out.stat().st_mode & 0o777 == 0o600
        assert descriptor["schema"] == "chio.process.connection.v1"
        assert descriptor["abi"] == "chio.process.abi.v1"
        assert "capability" not in descriptor
        return descriptor, ProcessClient(
            descriptor["socket_path"], descriptor["credential"]
        )

    @contextlib.contextmanager
    def serving(socket):
        host = subprocess.Popen(
            [
                binary,
                "process",
                "serve",
                "--state",
                str(state),
                "--socket",
                str(socket),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            assert select.select([host.stdout], [], [], 90)[0], "host startup timed out"
            line = host.stdout.readline()
            assert line, host.stderr.read()
            ready = json.loads(line)
            assert ready["ready"]
            assert ready["kernel_key"] == initialized["kernel_key"]
            yield host
        finally:
            if host.poll() is None:
                host.send_signal(signal.SIGTERM)
            try:
                host.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                host.kill()
                host.communicate(timeout=10)
                raise

    initialized = cli("init", "--config", config_path, "--state", state)
    assert initialized["processes"] == 4
    assert state.stat().st_mode & 0o777 == 0o700
    cli("init", "--config", config_path, "--state", state, success=False)
    # The host records the ABI it was initialized under and the build that
    # wrote it; state recorded under another ABI is refused before anything
    # opens it, and the original bytes serve again once restored.
    host_record = state / "host.json"
    recorded = host_record.read_bytes()
    host_json = json.loads(recorded)
    assert host_json["abi"] == "chio.process.abi.v1"
    assert host_json["written_by"].startswith("chio-cli ")
    host_record.write_bytes(
        json.dumps({**host_json, "abi": "chio.process.abi.v0"}).encode()
    )
    refused = cli(
        "credential",
        "--state",
        state,
        "--process",
        "publisher",
        "--socket",
        sockets / "refused.sock",
        "--out",
        descriptors / "refused.json",
        success=False,
    )
    assert "process ABI chio.process.abi.v0" in refused
    assert not (descriptors / "refused.json").exists()
    status = cli("status", "--state", state)
    assert status["abi"] == {
        "serving": "chio.process.abi.v1",
        "host": "chio.process.abi.v0",
        "written_by": host_json["written_by"],
    }
    host_record.write_bytes(recorded)
    socket = sockets / "first.sock"
    descriptor, publisher = connection("publisher", "publisher.json", socket)
    reader_descriptor, reader = connection("reader", "reader.json", socket)
    assert [tool["tool_name"] for tool in descriptor["tools"]] == ["append"]
    assert [tool["tool_name"] for tool in reader_descriptor["tools"]] == ["read"]
    with serving(socket) as host:
        assert publisher.inspect()["depth"] == 2
        first = publisher.invoke(
            "publish-report", "reports", "append", {"report": "kernel host recovery"}
        )
        assert first["verdict"] == "allow", first
        assert first["terminal_state"]["state"] == "completed", first
        denied = reader.invoke(
            "forbidden", "reports", "append", {"report": "forbidden"}
        )
        assert denied["verdict"] == "deny", denied
        try:
            publisher.invoke(
                "publish-report", "reports", "append", {"report": "changed"}
            )
            raise AssertionError("payload rebind allowed")
        except WorkerError as failure:
            assert failure.code == "conflict", failure
        failure = cli(
            "credential",
            "--state",
            state,
            "--process",
            "reader",
            "--socket",
            socket,
            "--out",
            descriptors / "live.json",
            success=False,
        )
        assert "already in use" in failure
        assert not (descriptors / "live.json").exists()
        failure = cli(
            "serve",
            "--state",
            state,
            "--socket",
            sockets / "competing.sock",
            success=False,
        )
        assert "already in use" in failure
        host.kill()
        host.wait(timeout=10)
    assert socket.exists(), "crash must leave the old socket entry"
    # A new endpoint after abrupt death avoids deleting an unverified socket.
    socket = sockets / "recovered.sock"
    rotated_descriptor, publisher = connection("publisher", "rotated.json", socket)
    assert rotated_descriptor["credential"] != descriptor["credential"]
    cli("revoke", "--state", state, "--process", "reader")
    _, fresh_reader = connection("reader", "reader-rotated.json", socket)
    with serving(socket):
        replay = publisher.invoke(
            "publish-report", "reports", "append", {"report": "kernel host recovery"}
        )
        assert replay["receipt_json"] == first["receipt_json"]
        assert replay["output"] == first["output"]
        revoked = ProcessClient(str(socket), reader_descriptor["credential"])
        try:
            revoked.inspect()
            raise AssertionError("revoked credential accepted")
        except WorkerError as failure:
            assert failure.code == "unauthenticated", failure
        # Publication and the denied sibling consumed two logical calls.
        # Eight reads exhaust the shared root ceiling across both subtrees.
        for index in range(8):
            read = fresh_reader.invoke(
                f"read-{index}", "reports", "read", {"path": "source.txt"}
            )
            assert read["verdict"] == "allow", read
        try:
            publisher.invoke("over-budget", "reports", "append", {"report": "extra"})
            raise AssertionError("shared call ceiling bypassed")
        except WorkerError as failure:
            assert failure.code == "limit_reached", failure
        recovered_at_limit = publisher.invoke(
            "publish-report", "reports", "append", {"report": "kernel host recovery"}
        )
        assert recovered_at_limit["receipt_json"] == first["receipt_json"]
    assert not socket.exists(), "graceful shutdown removes its own socket"
    count = cli("cancel", "--state", state, "--process", "writer")
    assert count["cancelled_processes"] == 2
    with serving(socket):
        try:
            publisher.invoke(
                "publish-report",
                "reports",
                "append",
                {"report": "kernel host recovery"},
            )
            raise AssertionError("cancelled process output released")
        except WorkerError as failure:
            assert failure.code == "cancelled", failure
    policy.write_text(original_policy + "\n# changed deployment\n")
    assert "policy changed" in cli(
        "serve", "--state", state, "--socket", socket, success=False
    )
    policy.write_text(original_policy)
    publications.with_suffix(".changed").touch()
    assert "tool definitions changed" in cli(
        "serve", "--state", state, "--socket", socket, success=False
    )
    assert len(publications.read_text().splitlines()) == 1
    print(
        json.dumps(
            {
                "receipt_json": first["receipt_json"],
                "kernel_key": initialized["kernel_key"],
                "publications": 1,
            }
        )
    )


if __name__ == "__main__":
    if sys.argv[1] == "--mcp":
        mcp(Path(sys.argv[2]))
    else:
        with tempfile.TemporaryDirectory(prefix="chio-process-host-") as temporary:
            exercise(sys.argv[1], Path(temporary))

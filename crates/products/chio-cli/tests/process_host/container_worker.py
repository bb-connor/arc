"""Worker code passed as literal Python argv inside the qualification image."""

import json
import os
import socket
import sys
import time
from pathlib import Path

from chio_process import ProcessClient

bootstrap = json.load(sys.stdin)
assert bootstrap["schema"] == "chio.process.worker-bootstrap.v1"
connection = bootstrap["connection"]
data = bootstrap["input"]
if "configuration" in data:
    data = data["configuration"] | data["task"]
client = ProcessClient(connection["socket_path"], connection["credential"])
assert connection["socket_path"] == "/run/chio/process.sock"
assert os.getuid() == data["uid"] != 0
status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines())
assert int(status["CapEff"].strip(), 16) == 0
assert status["NoNewPrivs"].strip() == "1"
assert status["Seccomp"].strip() == "2"
assert Path("/sys/fs/cgroup/memory.max").read_text().strip() == str(512 * 1024 * 1024)
assert Path("/sys/fs/cgroup/memory.swap.max").read_text().strip() == "0"
assert Path("/sys/fs/cgroup/pids.max").read_text().strip() == "64"
quota, period = map(int, Path("/sys/fs/cgroup/cpu.max").read_text().split())
assert quota == period
assert not Path("/var/run/docker.sock").exists()
assert not Path(data["state"]).exists()
try:
    Path("/outside-work").write_text("forbidden")
except OSError:
    pass
else:
    raise AssertionError("root filesystem is writable")
assert sorted(path.name for path in Path("/sys/class/net").iterdir()) == ["lo"]
with socket.socket() as probe:
    probe.settimeout(1)
    try:
        probe.connect(("192.0.2.1", 443))
    except OSError:
        pass
    else:
        raise AssertionError("external network reachable")
mode = data["mode"]
if mode == "supervision":

    def invoke(key, tool, arguments):
        response = client.invoke(key, "chio-process", tool, arguments, known_outcome_only=True)
        assert response["verdict"] == "allow", response
        print(json.dumps({"receipt_json": response["receipt_json"]}), flush=True)
        return response["output"]["value"]

    def join(key, process):
        checkpoint = client.inspect()["checkpoint"]
        state = checkpoint["value"] or {}
        poll = state.get(key, 0)
        result = invoke(f"{key}-{poll}", "settle_children", {"children": [process]})
        if not result["complete"]:
            state[key] = poll + 1
            client.checkpoint(checkpoint["revision"], state)
            raise SystemExit(75)
        return result

    failed = invoke("primary", "spawn_work", {"input": {"mode": "fail"}, "budget_share_bps": 3000})
    assert not join("join-primary", failed["process"])["successful"]
    fallback = invoke(
        "fallback", "spawn_work", {"input": {"mode": "complete"}, "budget_share_bps": 3000}
    )
    assert join("join-fallback", fallback["process"])["successful"]
    raise SystemExit(0)
if mode == "fail":
    raise SystemExit(1)
if mode == "parallel":
    client.inspect()
    Path("/work/ready.json").write_text(json.dumps({"attempt": bootstrap["attempt"]}))
    while True:
        time.sleep(0.05)
if mode == "flood":
    while True:
        os.write(1, b"x" * 8192)
if mode == "timeout":
    time.sleep(90)
    raise AssertionError("timeout was not enforced")
result = client.invoke(
    "publish", "chio-ipc", "send_jobs", {"message_key": "one", "payload": "one effect"}
)
assert result["verdict"] == "allow", result
messages = client.invoke("read", "chio-ipc", "receive_jobs", {"after_sequence": "0", "limit": 10})
assert len(messages["output"]["value"]["messages"]) == 1
event = {
    "attempt": bootstrap["attempt"],
    "connection": connection,
    "receipt_json": result["receipt_json"],
    "messages": 1,
}
Path("/work/ready.json").write_text(json.dumps(event))
if mode == "host-death":
    while not Path("/work/continue").exists():
        time.sleep(0.05)
print(json.dumps({key: value for key, value in event.items() if key != "connection"}))
print(connection["credential"], flush=True)
if mode == "worker-death" and bootstrap["attempt"] == 1:
    os._exit(77)

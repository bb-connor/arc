#!/usr/bin/env bash
set -euo pipefail

EXAMPLE_ROOT="$(cd "$(dirname "$0")" && pwd)"
ARTIFACT_ROOT="${EXAMPLE_ROOT}/.artifacts/$(date -u +"%Y%m%dT%H%M%SZ")"
LOG_DIR="${ARTIFACT_ROOT}/logs"
mkdir -p "${LOG_DIR}"

python3 - "${EXAMPLE_ROOT}" "${ARTIFACT_ROOT}" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

example_root = Path(sys.argv[1])
artifacts = Path(sys.argv[2])
logs = artifacts / "logs"

with (logs / "edge.log").open("w", encoding="utf-8") as edge_log:
    proc = subprocess.Popen(
        [str(example_root / "run-edge.sh"), "serve"],
        cwd=example_root,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=edge_log,
        text=True,
        bufsize=1,
    )

    def rpc(message: dict):
        assert proc.stdin is not None
        proc.stdin.write(json.dumps(message) + "\n")
        proc.stdin.flush()
        assert proc.stdout is not None
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("edge exited before responding")
        return json.loads(line)

    listed = rpc(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "session/list_capabilities",
            "params": {},
        }
    )
    invoked = rpc(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tool/invoke",
            "params": {
                "capabilityId": "hello_tool",
                "arguments": {"name": "world"},
            },
        }
    )
    streamed = rpc(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tool/stream",
            "params": {
                "capabilityId": "hello_tool",
                "arguments": {"name": "world"},
            },
        }
    )
    task_id = streamed["result"]["task"]["id"]
    resumed = rpc(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tool/resume",
            "params": {"taskId": task_id},
        }
    )

    proc.terminate()
    proc.wait(timeout=30)

(artifacts / "list-capabilities.json").write_text(
    json.dumps(listed, indent=2), encoding="utf-8"
)
(artifacts / "tool-invoke.json").write_text(
    json.dumps(invoked, indent=2), encoding="utf-8"
)
(artifacts / "tool-stream.json").write_text(
    json.dumps(streamed, indent=2), encoding="utf-8"
)
(artifacts / "tool-resume.json").write_text(
    json.dumps(resumed, indent=2), encoding="utf-8"
)

assert listed["result"]["capabilities"][0]["id"] == "hello_tool", listed
assert invoked["result"]["success"] is True, invoked
assert invoked["result"]["metadata"]["chio"]["authorityPath"] == "cross_protocol_orchestrator", invoked
assert invoked["result"]["metadata"]["chio"]["receiptId"], invoked

assert streamed["result"]["task"]["status"] == "working", streamed
assert streamed["result"]["task"]["metadata"]["chio"]["receiptPending"] is True, streamed

assert resumed["result"]["task"]["status"] == "completed", resumed
assert resumed["result"]["result"]["metadata"]["chio"]["receiptId"], resumed

print("hello-acp smoke passed")
print(f"artifacts: {artifacts}")
print(f"invoke receipt: {invoked['result']['metadata']['chio']['receiptId']}")
print(f"stream receipt: {resumed['result']['result']['metadata']['chio']['receiptId']}")
PY

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

agent_card = json.loads(
    subprocess.check_output(
        [str(example_root / "run-edge.sh"), "agent-card"],
        cwd=example_root,
        text=True,
    )
)
(artifacts / "agent-card.json").write_text(json.dumps(agent_card, indent=2), encoding="utf-8")
assert agent_card["skills"][0]["id"] == "hello_task", agent_card

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

    send_response = rpc(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "message/send",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "world"}],
                }
            },
        }
    )

    stream_created = rpc(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "message/stream",
            "params": {
                "message": {
                    "role": "user",
                    "parts": [{"type": "text", "text": "world"}],
                }
            },
        }
    )
    task_id = stream_created["result"]["id"]
    task_resolved = rpc(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "task/get",
            "params": {"taskId": task_id},
        }
    )

    proc.terminate()
    proc.wait(timeout=30)

(artifacts / "send-response.json").write_text(
    json.dumps(send_response, indent=2), encoding="utf-8"
)
(artifacts / "stream-created.json").write_text(
    json.dumps(stream_created, indent=2), encoding="utf-8"
)
(artifacts / "task-get-response.json").write_text(
    json.dumps(task_resolved, indent=2), encoding="utf-8"
)

assert send_response["result"]["status"] == "completed", send_response
assert send_response["result"]["metadata"]["arc"]["authorityPath"] == "cross_protocol_orchestrator", send_response
assert send_response["result"]["metadata"]["arc"]["receiptId"], send_response

assert stream_created["result"]["status"] == "working", stream_created
assert stream_created["result"]["metadata"]["arc"]["receiptPending"] is True, stream_created

assert task_resolved["result"]["status"] == "completed", task_resolved
assert task_resolved["result"]["metadata"]["arc"]["receiptId"], task_resolved

print("hello-a2a smoke passed")
print(f"artifacts: {artifacts}")
print(f"send receipt: {send_response['result']['metadata']['arc']['receiptId']}")
print(f"stream receipt: {task_resolved['result']['metadata']['arc']['receiptId']}")
PY


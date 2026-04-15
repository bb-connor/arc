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
        if "id" not in message:
            return None
        assert proc.stdout is not None
        line = proc.stdout.readline()
        if not line:
            raise RuntimeError("edge exited before responding")
        return json.loads(line)

    initialize = rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    rpc({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
    listed = rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    called = rpc(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "hello_tool",
                "arguments": {"name": "world"},
            },
        }
    )

    proc.terminate()
    proc.wait(timeout=30)

(artifacts / "initialize-response.json").write_text(
    json.dumps(initialize, indent=2), encoding="utf-8"
)
(artifacts / "tools-list-response.json").write_text(
    json.dumps(listed, indent=2), encoding="utf-8"
)
(artifacts / "tool-call-response.json").write_text(
    json.dumps(called, indent=2), encoding="utf-8"
)

assert initialize["result"]["protocolVersion"], initialize
assert listed["result"]["tools"][0]["name"] == "hello_tool", listed
assert called["result"]["isError"] is False, called
assert called["result"]["structuredContent"]["message"] == "hello from mcp, world", called

bridge_raw = subprocess.check_output(
    [str(example_root / "run-edge.sh"), "bridge-call"],
    cwd=example_root,
    text=True,
)
bridge = json.loads(bridge_raw)
(artifacts / "bridge-call.json").write_text(json.dumps(bridge, indent=2), encoding="utf-8")
assert bridge["receipt_id"], bridge

print("hello-mcp smoke passed")
print(f"artifacts: {artifacts}")
print(f"bridge receipt: {bridge['receipt_id']}")
PY


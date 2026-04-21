#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v cargo >/dev/null 2>&1; then
  echo "cross-protocol runtime qualification requires cargo on PATH" >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "cross-protocol runtime qualification requires python3 on PATH" >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "cross-protocol runtime qualification requires npm on PATH" >&2
  exit 1
fi

if ! command -v go >/dev/null 2>&1; then
  echo "cross-protocol runtime qualification requires go on PATH" >&2
  exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
  echo "cross-protocol runtime qualification requires uv on PATH" >&2
  exit 1
fi

if ! command -v dotnet >/dev/null 2>&1; then
  echo "cross-protocol runtime qualification requires dotnet on PATH" >&2
  exit 1
fi

if ! command -v java >/dev/null 2>&1; then
  echo "cross-protocol runtime qualification requires java on PATH" >&2
  exit 1
fi

output_root="target/release-qualification/cross-protocol-runtime"
log_root="${output_root}/logs"
manifest_path="${output_root}/artifact-manifest.json"
checksum_path="${output_root}/SHA256SUMS"
report_path="${output_root}/qualification-report.md"
matrix_src="docs/standards/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json"
matrix_snapshot="${output_root}/CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json"

rm -rf "${output_root}"
mkdir -p "${log_root}"

run_and_log() {
  local name="$1"
  shift
  local log_path="${log_root}/${name}.log"
  echo "==> ${name}"
  "$@" 2>&1 | tee "${log_path}"
}

python3 -m json.tool "${matrix_src}" >/dev/null
cp "${matrix_src}" "${matrix_snapshot}"

run_and_log chio-cross-protocol cargo test -p chio-cross-protocol
run_and_log chio-mcp-edge cargo test -p chio-mcp-edge
run_and_log chio-acp-edge cargo test -p chio-acp-edge
run_and_log chio-a2a-edge cargo test -p chio-a2a-edge
run_and_log chio-http-core cargo test -p chio-http-core
run_and_log chio-api-protect cargo test -p chio-api-protect
run_and_log chio-tower cargo test -p chio-tower
run_and_log chio-openai cargo test -p chio-openai-adapter
run_and_log chio-acp-proxy cargo test -p chio-acp-proxy
run_and_log ts-node-http sh -lc 'cd sdks/typescript/packages/node-http && npm test'
run_and_log ts-express sh -lc 'cd sdks/typescript/packages/express && npm test'
run_and_log go-sdk sh -lc 'cd sdks/go/chio-go-http && go test ./...'
run_and_log python-sdk sh -lc 'cd sdks/python/chio-sdk-python && uv run --extra dev pytest tests/test_models.py tests/test_client.py'
run_and_log python-asgi sh -lc 'cd sdks/python/chio-asgi && uv run --extra dev pytest tests/test_middleware.py'
run_and_log python-django sh -lc 'cd sdks/python/chio-django && uv run --extra dev pytest tests/test_middleware.py'
run_and_log python-fastapi sh -lc 'cd sdks/python/chio-fastapi && uv run --extra dev pytest tests/test_dependencies.py'
run_and_log jvm-sdk sh -lc 'cd sdks/jvm/chio-spring-boot && ./gradlew test --no-daemon'
run_and_log dotnet-sdk sh -lc 'cd sdks/dotnet/ChioMiddleware && dotnet test ChioMiddleware.sln'

cat >"${report_path}" <<'EOF'
# Cross-Protocol Runtime Qualification Gate

This artifact bundle captures the local post-v3.15 qualification evidence for
Chio's bounded cross-protocol runtime substrate.

Decision:

- Chio ships a cryptographically signed, fail-closed governance kernel and a
  bounded protocol-aware cross-protocol execution fabric across HTTP APIs,
  MCP, OpenAI tool execution, A2A skills, and ACP capabilities.
- On supported authoritative paths, execution is kernel-mediated,
  receipt-bearing, and explicit about lifecycle and fidelity limits,
  including authoritative deferred-task mediation on A2A and ACP public
  surfaces.
- The stronger technical control-plane thesis is evaluated by the successor
  gate in `./scripts/qualify-universal-control-plane.sh`, so this lane retains
  the bounded protocol-aware fabric claim as its ceiling.

Not yet qualified:

- Chio does not yet claim a fully realized universal protocol-to-protocol
  orchestration layer or a proved "comptroller of the agent economy" position.

Executed command set:

- `cargo test -p chio-cross-protocol`
- `cargo test -p chio-mcp-edge`
- `cargo test -p chio-acp-edge`
- `cargo test -p chio-a2a-edge`
- `cargo test -p chio-http-core`
- `cargo test -p chio-api-protect`
- `cargo test -p chio-tower`
- `cargo test -p chio-openai-adapter`
- `cargo test -p chio-acp-proxy`
- `npm test` in `sdks/typescript/packages/node-http`
- `npm test` in `sdks/typescript/packages/express`
- `go test ./...` in `sdks/go/chio-go-http`
- `uv run --extra dev pytest tests/test_models.py tests/test_client.py` in `sdks/python/chio-sdk-python`
- `uv run --extra dev pytest tests/test_middleware.py` in `sdks/python/chio-asgi`
- `uv run --extra dev pytest tests/test_middleware.py` in `sdks/python/chio-django`
- `uv run --extra dev pytest tests/test_dependencies.py` in `sdks/python/chio-fastapi`
- `./gradlew test --no-daemon` in `sdks/jvm/chio-spring-boot`
- `dotnet test ChioMiddleware.sln` in `sdks/dotnet/ChioMiddleware`

Supporting machine-readable gate:

- `CHIO_CROSS_PROTOCOL_QUALIFICATION_MATRIX.json`
- successor gate: `CHIO_UNIVERSAL_CONTROL_PLANE_QUALIFICATION_MATRIX.json`
EOF

python3 - <<'PY' "${output_root}" "${checksum_path}" "${manifest_path}"
from __future__ import annotations

import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

output_root = Path(sys.argv[1])
checksum_path = Path(sys.argv[2])
manifest_path = Path(sys.argv[3])

entries = []
for artifact in sorted(output_root.rglob("*")):
    if not artifact.is_file():
        continue
    if artifact in {checksum_path, manifest_path}:
        continue
    payload = artifact.read_bytes()
    entries.append(
        {
            "path": artifact.relative_to(output_root).as_posix(),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
    )

checksum_path.write_text(
    "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in entries)
)

manifest = {
    "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "scope": "cross_protocol_runtime_qualification",
    "claimLevel": "bounded_protocol_aware_execution_fabric",
    "decision": "bounded_claim_qualified_use_universal_control_plane_gate_for_stronger_claim",
    "claim": "cryptographically signed, fail-closed governance kernel and bounded protocol-aware cross-protocol execution fabric on the qualified authoritative paths",
    "successorGate": "./scripts/qualify-universal-control-plane.sh",
    "artifacts": entries,
}

manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
PY

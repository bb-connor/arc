#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

python3 - <<'PY'
from pathlib import Path

checks = [
    {
        "file": "crates/chio-mcp-edge/src/runtime.rs",
        "required": [
            "evaluate_tool_call_operation",
            "self.kernel.evaluate_session_operation",
            "evaluate_tool_call_operation_with_nested_flow_client",
        ],
    },
    {
        "file": "crates/chio-api-protect/src/evaluator.rs",
        "required": [
            "self.authority.evaluate",
            "capability_id",
            "Decision::Deny",
        ],
    },
    {
        "file": "crates/chio-openapi/src/proxy.rs",
        "required": [
            "evaluate",
            "receipt",
        ],
        "optional": True,
    },
]

failures = []
for check in checks:
    path = Path(check["file"])
    if not path.exists():
        if check.get("optional"):
            continue
        failures.append(f"missing file: {path}")
        continue
    text = path.read_text(encoding="utf-8")
    for required in check["required"]:
        if required not in text:
            failures.append(f"{path} missing mediation marker: {required}")

adapter_roots = [
    Path("crates/chio-mcp-edge/src"),
    Path("crates/chio-mcp-adapter/src"),
    Path("crates/chio-api-protect/src"),
    Path("crates/chio-openapi/src"),
]
for root in adapter_roots:
    if not root.exists():
        continue
    for path in root.rglob("*.rs"):
        text = path.read_text(encoding="utf-8")
        forbidden_hits = []
        for marker in ["Command::new", ".spawn(", ".invoke("]:
            if marker in text and "evaluate" not in text and "kernel" not in text:
                forbidden_hits.append(marker)
        if forbidden_hits:
            failures.append(
                f"{path} contains side-effect marker(s) without local mediation marker: {forbidden_hits}"
            )

if failures:
    raise SystemExit("adapter no-bypass check failed:\n" + "\n".join(failures))
PY

echo "Adapter no-bypass check passed"

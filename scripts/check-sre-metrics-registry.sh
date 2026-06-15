#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

registry="$(mktemp)"
observed="$(mktemp)"
trap 'rm -f "${registry}" "${observed}"' EXIT

cut -d'|' -f1 crates/observability/chio-metrics-spec/metrics.snapshot | sort -u > "${registry}"

# Scope includes the edge crates that consume the registry plus
# `chio-wasm-guards`. The scan is anchored at `crates/<name>/src` to avoid
# pulling matches out of `target/` artifacts.
python3 - "${observed}" <<'PY'
from pathlib import Path
import re
import sys

out_path = Path(sys.argv[1])
roots = [
    "crates/observability/chio-metrics-spec",
    "crates/kernel/chio-kernel/src",
    "crates/protocol/chio-mcp-edge/src",
    "crates/protocol/chio-acp-edge/src",
    "crates/protocol/chio-a2a-edge/src",
    "crates/platform/chio-http-core/src",
    "crates/economy/chio-anchor/src",
    "crates/trust/chio-federation/src",
    "crates/trust/chio-pheromone-relay/src",
    "crates/guards/chio-wasm-guards/src",
    "crates/observability/chio-siem",
    "deploy/prometheus",
    ".github/workflows",
    "scripts",
    "docs/operator-runbook",
]
metric_re = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"chio_[a-z0-9_]*(?:seconds|total|depth|bytes|ready|size)"
    r"(?![A-Za-z0-9_])"
)
metrics: set[str] = set()

for root in roots:
    path = Path(root)
    if not path.exists():
        raise SystemExit(f"check-sre-metrics-registry.sh: scan path missing: {root}")
    files = [path] if path.is_file() else (item for item in path.rglob("*") if item.is_file())
    for file_path in files:
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError as error:
            raise SystemExit(
                f"check-sre-metrics-registry.sh: failed to read {file_path}: {error}"
            ) from error
        metrics.update(metric_re.findall(text))

body = "\n".join(sorted(metrics))
out_path.write_text(f"{body}\n" if body else "", encoding="utf-8")
PY

failed=0
while IFS= read -r metric; do
  if [[ -z "${metric}" ]]; then
    continue
  fi
  if ! grep -Fxq "${metric}" "${registry}"; then
    echo "unregistered Chio metric name: ${metric}" >&2
    failed=1
  fi
done < "${observed}"

if [[ "${failed}" -ne 0 ]]; then
  echo "add new metric names to crates/observability/chio-metrics-spec before using them" >&2
  exit 1
fi

echo "SRE metric registry gate passed"

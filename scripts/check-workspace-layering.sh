#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v rg >/dev/null 2>&1; then
  echo "check-workspace-layering.sh requires rg on PATH" >&2
  exit 1
fi

domain_manifests=(
  "crates/arc-core/Cargo.toml"
  "crates/arc-manifest/Cargo.toml"
  "crates/arc-did/Cargo.toml"
  "crates/arc-guards/Cargo.toml"
  "crates/arc-policy/Cargo.toml"
  "crates/arc-reputation/Cargo.toml"
  "crates/arc-credentials/Cargo.toml"
  "crates/arc-kernel/Cargo.toml"
)

blocked_workspace_paths='path = "\\.\\./(arc-cli|arc-control-plane|arc-hosted-mcp)"'
blocked_transport_deps='^(clap|axum|reqwest)\\s*='
failed=0

for manifest in "${domain_manifests[@]}"; do
  if rg -n "${blocked_workspace_paths}" "${manifest}" >/dev/null; then
    echo "blocked workspace dependency found in ${manifest}" >&2
    rg -n "${blocked_workspace_paths}" "${manifest}" >&2 || true
    failed=1
  fi

  if rg -n "${blocked_transport_deps}" "${manifest}" >/dev/null; then
    echo "blocked transport/runtime dependency found in ${manifest}" >&2
    rg -n "${blocked_transport_deps}" "${manifest}" >&2 || true
    failed=1
  fi
done

if [[ "${failed}" -ne 0 ]]; then
  exit 1
fi

echo "workspace layering checks passed"

#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v rg >/dev/null 2>&1; then
  echo "check-workspace-layering.sh requires rg on PATH" >&2
  exit 1
fi

domain_manifests=(
  "crates/pact-core/Cargo.toml"
  "crates/pact-manifest/Cargo.toml"
  "crates/pact-did/Cargo.toml"
  "crates/pact-guards/Cargo.toml"
  "crates/pact-policy/Cargo.toml"
  "crates/pact-reputation/Cargo.toml"
  "crates/pact-credentials/Cargo.toml"
  "crates/pact-kernel/Cargo.toml"
)

blocked_workspace_paths='path = "\\.\\./(pact-cli|pact-control-plane|pact-hosted-mcp)"'
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

#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT

mkdir -p "${fixture}"/{crates,spec,sdks,scripts,docs,formal,xtask}
cp "${root}/scripts/check-chio-owned-v1-only.sh" "${fixture}/scripts/"

printf '%s\n' \
  'const SCHEMA: &str = "chio.cage-migration-posture.v2";' \
  > "${fixture}/crates/independent-security.rs"
bash "${fixture}/scripts/check-chio-owned-v1-only.sh" >/dev/null

printf 'struct CapabilityToken%s;\n' 'V2' > "${fixture}/crates/core-capability.rs"
if bash "${fixture}/scripts/check-chio-owned-v1-only.sh" >/dev/null 2>&1; then
  echo "future capability token unexpectedly passed the core v1 gate" >&2
  exit 1
fi

rm "${fixture}/crates/core-capability.rs"
printf 'const PATH: &str = "receipt/%s.schema.json";\n' 'v2' \
  > "${fixture}/crates/core-receipt.rs"
if bash "${fixture}/scripts/check-chio-owned-v1-only.sh" >/dev/null 2>&1; then
  echo "future receipt schema unexpectedly passed the core v1 gate" >&2
  exit 1
fi

echo "Core v1 version gate contract passed"

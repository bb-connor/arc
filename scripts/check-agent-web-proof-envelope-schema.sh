#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

run_case() {
  local label="$1" expected="$2"
  ./scripts/run-exact-cargo-test-inventory.sh --label "${label}" \
    --allow-filtered --expected "${expected}" -- \
    cargo test -p chio-agent-web-interop --test agent_web_interop "${expected}"
}

run_case "published Agent Web schema fixtures" \
  core_tests::published_agent_web_schemas_accept_supported_projection_fixtures
run_case "published v1 proof envelope schema" \
  core_tests::published_v1_proof_envelope_schema_accepts_legacy_shape
run_case "published v2 proof envelope schema" \
  core_tests::published_v2_proof_envelope_schema_requires_scope_and_unique_receipts
run_case "signed v1 envelope verification" \
  core_tests::verifier_accepts_signed_legacy_v1_envelope

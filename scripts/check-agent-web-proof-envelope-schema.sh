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
run_case "published v2 proof envelope schema" \
  core_tests::published_v2_proof_envelope_schema_requires_scope_and_unique_receipts
run_case "unsupported envelope schema refusal" \
  core_tests::verifier_refuses_unsupported_envelope_schema

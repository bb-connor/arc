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
  core_tests::published_proof_envelope_schema_requires_scope_and_unique_receipts
run_case "unsupported envelope schema refusal" \
  core_tests::verifier_refuses_unsupported_envelope_schema
run_case "unsupported envelope payload schema refusal" \
  core_tests::verifier_refuses_unsupported_envelope_payload_schema
run_case "required envelope passport scope" \
  core_tests::verifier_refuses_envelope_without_passport_scope

#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

runner="scripts/check-consumer-boundaries.sh"
test -x "${runner}"
bash -n "${runner}"
test "$(grep -c '^  [a-z].* \\$' "${runner}")" -eq 8
test "$(grep -c '^run_case ' "${runner}")" -eq 13
test "$(grep -c '^run_target ' "${runner}")" -eq 2
grep -Fq 'run_target "stdio MCP early profile rejection" mcp_serve_rejects_flow_before_store_acquisition_and_launch_policy_loading cargo test -p chio-cli --test mcp_startup_security' "${runner}"
grep -Fq 'run_target "Rust generated protocol corpus" generated_rust_shapes_parse_reject_and_round_trip_shared_fixtures cargo test -p chio-core-types --test protocol_primitives_generated' "${runner}"
grep -Fq 'run_case "remote MCP retained authorization" tests::restored_authorization_matches_the_handshake_without_upgrading_legacy_sessions cargo test -p chio-mcp-remote --lib' "${runner}"
grep -Fq 'run_case "remote MCP ready-session restart" mcp_serve_http_ready_sessions_survive_restart_and_resume_authenticated_calls cargo test -p chio-cli --test mcp_serve_http' "${runner}"
grep -Fq 'run_case "remote MCP restart policy tightening" mcp_serve_http_ready_sessions_reissue_capabilities_after_policy_tightening cargo test -p chio-cli --test mcp_serve_http' "${runner}"
grep -Fq -- '-- cargo test -p chio-conformance --test consumer_boundary --locked' "${runner}"
grep -Fq './scripts/check-protocol-peer-negotiation.sh' "${runner}"
grep -Fq './scripts/check-adapter-no-bypass.sh' "${runner}"
for workflow in .github/workflows/sdk-parity.yml .github/workflows/enterprise-hardening.yml; do
  grep -Fq './scripts/check-consumer-sdk-parity.sh' "${workflow}"
done
grep -Fq 'npm run build --workspace @chio-protocol/node-http' scripts/check-consumer-sdk-parity.sh

# The shared harness supplies behavioral missing/renamed/ignored/zero-match
# calibration. Its public peer wrapper also calibrates the single-case pattern.
bash scripts/tests/run-exact-cargo-test-inventory.test.sh
bash scripts/tests/check-protocol-peer-negotiation.test.sh
echo "Consumer boundary gate contract passed"

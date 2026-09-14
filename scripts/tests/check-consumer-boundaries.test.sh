#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

runner="scripts/check-consumer-boundaries.sh"
test -x "${runner}"
bash -n "${runner}"
test "$(grep -c '^  [a-z].* \\$' "${runner}")" -eq 8
test "$(grep -c '^run_case ' "${runner}")" -eq 23
test "$(grep -c '^run_target ' "${runner}")" -eq 2
grep -Fq 'run_target "stdio MCP early profile rejection" mcp_serve_rejects_flow_before_store_acquisition_and_launch_policy_loading cargo test -p chio-cli --test mcp_startup_security' "${runner}"
grep -Fq 'run_target "Rust generated protocol corpus" generated_rust_shapes_parse_reject_and_round_trip_shared_fixtures cargo test -p chio-core-types --test protocol_primitives_generated' "${runner}"
grep -Fq 'run_case "remote MCP retained authorization" tests::restored_authorization_matches_the_handshake_without_upgrading_legacy_sessions cargo test -p chio-mcp-remote --lib' "${runner}"
grep -Fq 'run_case "signed receipt origin vocabulary" receipt_schemas_accept_signed_internal_origin_and_keep_closed_vocabulary cargo test -p chio-core-types --test wire_protocol_schema' "${runner}"
grep -Fq 'run_case "retained caller attachment capacity" admission_operation::tests::attachment_capacity::rich_native_caller_attachments_survive_outcome_append_and_persistence cargo test -p chio-kernel --lib' "${runner}"
grep -Fq 'run_case "remote MCP ready-session restart" mcp_serve_http_ready_sessions_survive_restart_and_resume_authenticated_calls cargo test -p chio-cli --test mcp_serve_http' "${runner}"
grep -Fq 'run_case "remote MCP restart policy tightening" mcp_serve_http_ready_sessions_reissue_capabilities_after_policy_tightening cargo test -p chio-cli --test mcp_serve_http' "${runner}"
grep -Fq 'run_case "supervisor HTTP readiness positive control" supervise::readiness::tests::an_http_endpoint_is_ready_only_on_a_success_status cargo test -p chio-cli --bin chio' "${runner}"
grep -Fq 'run_case "supervisor readiness redirect denial" supervise::readiness::security_tests::readiness_never_follows_same_or_cross_origin_redirects cargo test -p chio-cli --bin chio' "${runner}"
grep -Fq 'run_case "supervisor readiness response bounds" supervise::readiness::security_tests::readiness_caps_declared_and_streamed_response_bodies cargo test -p chio-cli --bin chio' "${runner}"
grep -Fq 'run_case "supervisor readiness exact response limit" supervise::readiness::security_tests::readiness_accepts_a_response_at_its_exact_byte_limit cargo test -p chio-cli --bin chio' "${runner}"
grep -Fq 'run_case "supervisor readiness invalid configuration" supervise::readiness::security_tests::readiness_rejects_invalid_targets_and_headers_before_launch cargo test -p chio-cli --bin chio' "${runner}"
grep -Fq 'run_case "supervisor readiness private addresses" supervise::readiness::security_tests::readiness_accepts_operator_selected_private_addresses cargo test -p chio-cli --bin chio' "${runner}"
grep -Fq 'run_case "operator readiness DNS deadline" operator_readiness::tests::dns_uses_the_async_resolver_inside_the_deadline cargo test -p chio-egress-contract --features reqwest-egress --lib' "${runner}"
grep -Fq 'run_case "supervisor readiness rejects before child launch" invalid_http_readiness_refuses_to_start_the_service cargo test -p chio-cli --test security_supervise' "${runner}"
grep -Fq -- '-- cargo test -p chio-conformance --test consumer_boundary --locked' "${runner}"
grep -Fq './scripts/check-protocol-peer-negotiation.sh' "${runner}"
grep -Fq './scripts/check-adapter-no-bypass.sh' "${runner}"
grep -Fq './scripts/check-http-egress-contract.sh' "${runner}"
for workflow in .github/workflows/sdk-parity.yml .github/workflows/enterprise-hardening.yml; do
  grep -Fq './scripts/check-consumer-sdk-parity.sh' "${workflow}"
done
grep -Fq 'npm run build --workspace @chio-protocol/node-http' scripts/check-consumer-sdk-parity.sh

# The shared harness supplies behavioral missing/renamed/ignored/zero-match
# calibration. Its public peer wrapper also calibrates the single-case pattern.
bash scripts/tests/run-exact-cargo-test-inventory.test.sh
bash scripts/tests/check-protocol-peer-negotiation.test.sh
echo "Consumer boundary gate contract passed"

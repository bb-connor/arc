#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export CARGO_INCREMENTAL=0
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"

# The whole target is an exact inventory. Adding, removing, ignoring or renaming
# an acceptance case requires reviewing this gate, not merely changing a filter.
./scripts/run-exact-cargo-test-inventory.sh --label "durable consumer boundaries" --expected \
  a2a_aggregate_capture_survives_consumer_restart \
  a2a_threshold_proposal_approval_and_restart_preserve_one_capture \
  acp_aggregate_capture_survives_consumer_restart \
  acp_threshold_proposal_approval_and_restart_preserve_one_capture \
  mcp_aggregate_capture_survives_consumer_restart \
  mcp_threshold_proposal_approval_and_restart_preserve_one_capture \
  native_aggregate_capture_survives_consumer_restart \
  native_threshold_proposal_approval_and_restart_preserve_one_capture \
  -- cargo test -p chio-conformance --test consumer_boundary --locked

run_case() {
  local label="$1" expected="$2"
  shift 2
  ./scripts/run-exact-cargo-test-inventory.sh --label "${label}" \
    --allow-filtered --expected "${expected}" -- "$@" --locked "${expected}"
}

run_case "MCP malformed profile before acquisition" runtime::runtime_tests::authorization::mcp_authorization_negotiation_rejects_malformed_profiles_before_session_acquisition cargo test -p chio-mcp-edge --lib
run_case "MCP profile recovery without upgrade" runtime::runtime_tests::authorization::restored_mcp_authorization_profile_is_exact_and_legacy_sessions_do_not_upgrade cargo test -p chio-mcp-edge --lib
run_case "MCP bound target authority" runtime::source_receipt_tests::mcp_target_executor_carries_source_receipt_context_into_kernel_receipt_metadata cargo test -p chio-mcp-edge --lib
run_case "remote MCP early profile rejection" tests::session_runtime::remote_session_factory_rejects_flow_before_launch_authority_or_store_acquisition cargo test -p chio-mcp-remote --lib
run_case "stdio MCP early profile rejection" mcp_serve_rejects_flow_before_store_acquisition_and_launch_policy_loading cargo test -p chio-cli --test mcp_startup_security
run_case "current signed manifest corpus" current_manifest_consumer_corpus_preserves_wire_and_registered_signature cargo test -p chio-manifest --test manifest_v2
run_case "Rust generated protocol corpus" generated_rust_shapes_parse_reject_and_round_trip_shared_fixtures cargo test -p chio-core-types --test protocol_primitives_generated
run_case "authoritative protocol schema corpus" protocol_primitives_shared_fixtures_match_authoritative_schemas cargo test -p chio-core-types --test wire_protocol_schema
run_case "Tower peer boundary" kernel_service::tests::kernel_service_rejects_unnegotiated_extensions_before_effect_or_receipt cargo test -p chio-tower --lib
run_case "OpenAI peer boundary" tests::openai_host_rejects_unnegotiated_authority_before_effect_or_receipt cargo test -p chio-openai-adapter --lib
run_case "OpenAI ordinary host flow rejection" tests::openai_ordinary_host_rejects_flow_required_manifest_before_exposure cargo test -p chio-openai-adapter --lib
run_case "provider fabric bounded profile" provider_verdict::tests::provider_fabric_rejects_unnegotiated_authorization_before_lowering cargo test -p chio-kernel --lib

./scripts/check-protocol-peer-negotiation.sh
./scripts/check-adapter-no-bypass.sh
echo "Consumer boundary Rust gate passed (SDK, M3 and composed gates remain separate)"

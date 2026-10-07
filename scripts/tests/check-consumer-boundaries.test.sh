#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."

runner="scripts/check-consumer-boundaries.sh"
test -x "${runner}"
bash -n "${runner}"
test "$(grep -c '^  [a-z].* \\$' "${runner}")" -eq 16
grep -Fq '  support::a2a_v1::pending_approval_preserves_caller_isolation_and_text_mode_through_cancel \' "${runner}"
grep -Fq '  support::a2a_v1::pending_approval_remains_observable_without_dispatch_or_new_receipts \' "${runner}"
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

# Exercise the actual producer's expected inventory against an independent
# execution fixture. Every continuation case must survive omission and
# same-count substitution controls.
python3 - <<'PY_CONTINUATION'
import shlex
import subprocess
import tempfile
from pathlib import Path

producer = Path("scripts/check-consumer-boundaries.sh").read_text()
invocation = producer[producer.index("./scripts/run-exact-cargo-test-inventory.sh"):]
invocation = shlex.split(invocation.split("\n\n", 1)[0].replace("\\\n", " "))
expected = invocation[invocation.index("--expected") + 1:invocation.index("--")]
legacy = [
    "a2a_aggregate_capture_survives_consumer_restart",
    "a2a_threshold_proposal_approval_and_restart_preserve_one_capture",
    "acp_aggregate_capture_survives_consumer_restart",
    "acp_threshold_proposal_approval_and_restart_preserve_one_capture",
    "mcp_aggregate_capture_survives_consumer_restart",
    "mcp_threshold_proposal_approval_and_restart_preserve_one_capture",
    "native_aggregate_capture_survives_consumer_restart",
    "native_threshold_proposal_approval_and_restart_preserve_one_capture",
    "support::a2a_v1::pending_approval_preserves_caller_isolation_and_text_mode_through_cancel",
    "support::a2a_v1::pending_approval_remains_observable_without_dispatch_or_new_receipts",
]
continuation = [
    "support::a2a_continuation_clock::transient_deadline_clock_failure_preserves_the_original_task_for_retry",
    "support::a2a_v1::continuation_error_does_not_restore_pending_approval_after_terminal_dispatch",
    "support::a2a_v1::continuation_conceals_inaccessible_tasks_and_preserves_the_original_owner",
    "support::a2a_v1::continuation_refuses_frozen_authority_changes_without_losing_pending_custody",
    "support::a2a_v1::signed_approval_cannot_resume_a_cancelled_v1_task",
    "support::a2a_v1::signed_approval_continuation_completes_the_original_v1_task",
]
names = legacy + continuation
with tempfile.TemporaryDirectory(prefix="chio-continuation-inventory-") as directory:
    listed, executed = Path(directory) / "list", Path(directory) / "run"
    listed.write_text("".join(f"{name}: test\n" for name in names))
    executed.write_text("".join(f"test {name} ... ok\n" for name in names)
        + "test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n")
    command = ["python3", "scripts/check-exact-cargo-test-inventory.py",
        "--label", "continuation producer", "--list-output", str(listed),
        "--run-output", str(executed)]
    subprocess.run(command + expected, check=True, capture_output=True, text=True)
    for name in continuation:
        for mutated in [
            [item for item in expected if item != name],
            ["substituted_continuation_case" if item == name else item for item in expected],
        ]:
            result = subprocess.run(command + mutated, capture_output=True, text=True)
            if result.returncode != 1 or "exact inventory mismatch" not in result.stderr:
                raise SystemExit(f"continuation inventory accepted or misdiagnosed {name}: {result}")
print("Continuation inventory rejects all six omissions and substitutions")
PY_CONTINUATION

# The shared harness supplies behavioral missing/renamed/ignored/zero-match
# calibration. Its public peer wrapper also calibrates the single-case pattern.
bash scripts/tests/run-exact-cargo-test-inventory.test.sh
bash scripts/tests/check-protocol-peer-negotiation.test.sh
echo "Consumer boundary gate contract passed"

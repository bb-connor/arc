#!/usr/bin/env python3
"""Ratchet the count of weak negative assertions per file in the security crates.

This is a net-count budget per file, not a per-site pin: a change that
strengthens one old assertion and adds one weak assertion elsewhere in the same
file passes at an unchanged count. That trade is visible in the diff, so review
of changed tests remains part of the contract until the baseline pins sites by
identity rather than by count.

`assert!(result.is_err())` in a fail-closed system is close to vacuous. Almost
any mistake produces an error, so the assertion passes when the code rejects for
the wrong reason, when an unrelated earlier validation rejects first, and often
when the feature under test does not exist at all. A negative test has to assert
which rule rejected: match the specific variant, or assert on the value that
`unwrap_err` returns.

A message argument does not help. `assert!(result.is_err(), "expected a stale
scope")` records what the author believed, and still passes if a different rule
fired, so it counts the same as the bare form here.

Scope: `crates/security`, `crates/kernel/chio-kernel` and
`crates/platform/chio-control-plane`, in test and production code alike.
Negative assertions live mostly in tests, which is exactly where the weakness
matters.

Baseline policy: the existing counts are debt, per file, and can only shrink.
Nothing here converts them, because most cannot be converted yet: several
distinct rejection rules currently share one error variant, which leaves an
author nothing more specific to assert. The conversions land per boundary as
each rule gets its own discriminant.

The baseline carries one expiry rather than a spread of them, because one change
retires all of it: once each rejection rule is distinguishable, every entry
becomes convertible at once. That is also why the entries carry no individual
rationale; they share this one, and repeating it per file would say nothing.
Renew only through `--ratchet`, which re-counts each file, never upward, drops
files that have none left, and moves the expiry forward but never back.
"""

from __future__ import annotations

import argparse
import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
import subprocess
import sys


SOURCE_PATTERNS = ("crates/*.rs", "crates/*.inc")
ASSERTION_ROOTS = (
    "crates/security/",
    "crates/kernel/chio-kernel/",
    "crates/platform/chio-control-plane/",
)

BASELINE_EXPIRES = "2027-01-31"

# Weak negative assertions per file. Entries are debt, not configuration.
BASELINE: dict[str, int] = {
    "crates/kernel/chio-kernel/src/admission_operation.part3.inc": 8,
    "crates/kernel/chio-kernel/src/admission_operation/authority_profile/tests.rs": 6,
    "crates/kernel/chio-kernel/src/admission_operation/capture_tests.rs": 1,
    "crates/kernel/chio-kernel/src/admission_operation/dpop_claim/tests.rs": 1,
    "crates/kernel/chio-kernel/src/admission_operation/execution_nonce/profile.rs": 4,
    "crates/kernel/chio-kernel/src/admission_operation/native_flow_observation.rs": 5,
    "crates/kernel/chio-kernel/src/admission_operation/native_input_join/tests.rs": 12,
    "crates/kernel/chio-kernel/src/admission_operation/projection/channel_terminal_tests.rs": 8,
    "crates/kernel/chio-kernel/src/admission_operation/remote_projection.rs": 3,
    "crates/kernel/chio-kernel/src/admission_operation/runtime_participant.rs": 4,
    "crates/kernel/chio-kernel/src/admission_operation/sequencer.rs": 1,
    "crates/kernel/chio-kernel/src/admission_operation_tests.rs": 2,
    "crates/kernel/chio-kernel/src/admission_operation_tests/terminal_projection.rs": 1,
    "crates/kernel/chio-kernel/src/authority.rs": 2,
    "crates/kernel/chio-kernel/src/authority/aggregate.rs": 8,
    "crates/kernel/chio-kernel/src/caller_delivery/tests.rs": 14,
    "crates/kernel/chio-kernel/src/capability_lineage.rs": 1,
    "crates/kernel/chio-kernel/src/dispatch_status_tests.rs": 3,
    "crates/kernel/chio-kernel/src/dpop.rs": 6,
    "crates/kernel/chio-kernel/src/dpop/authority/tests.rs": 13,
    "crates/kernel/chio-kernel/src/dpop/identity/tests.rs": 5,
    "crates/kernel/chio-kernel/src/dpop/replay_source/snapshot/tests.rs": 11,
    "crates/kernel/chio-kernel/src/dpop/replay_source/tests.rs": 21,
    "crates/kernel/chio-kernel/src/finding_pool_tests.rs": 2,
    "crates/kernel/chio-kernel/src/governed_approval_replay.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/caller/tests.rs": 8,
    "crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/caller/tests/custody.rs": 5,
    "crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/caller/tests/participants.rs": 7,
    "crates/kernel/chio-kernel/src/kernel/dispatch/timer_probe_tests.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/kernel_struct.rs": 3,
    "crates/kernel/chio-kernel/src/kernel/recovery_gate.rs": 8,
    "crates/kernel/chio-kernel/src/kernel/tests/automatic_active_response_fence.rs": 3,
    "crates/kernel/chio-kernel/src/kernel/tests/boot_receipts.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/tests/budget.rs": 6,
    "crates/kernel/chio-kernel/src/kernel/tests/capability_liveness.rs": 9,
    "crates/kernel/chio-kernel/src/kernel/tests/capability_validation.rs": 4,
    "crates/kernel/chio-kernel/src/kernel/tests/chio_runtime.rs": 8,
    "crates/kernel/chio-kernel/src/kernel/tests/chio_runtime_url_elicitation.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/tests/dispatch_credentials.rs": 4,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/authority_profile.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/dispatch_commit_failure.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/dpop_acquisition.rs": 7,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/federation_context.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/federation_context/evidence.rs": 5,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/federation_context/recovery_isolation.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/governed_acquisition.rs": 3,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/native_acquisition.rs": 3,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/native_acquisition/input.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/native_dispatch_ledger.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/native_egress.rs": 12,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/return_context.rs": 5,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/return_signing.rs": 3,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/return_signing/callbacks.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/review_regressions.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/runtime_participant.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/runtime_participant/acquisition.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/runtime_participant/selection.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/security_binding.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/security_binding/native_authority.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/security_binding/native_authority/codec.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/tests/durable_admission/security_binding/retention.rs": 4,
    "crates/kernel/chio-kernel/src/kernel/tests/execution_nonce.rs": 3,
    "crates/kernel/chio-kernel/src/kernel/tests/immediate_dispatch_revalidation.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/invocation_dispatch.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/nested_url_side_effects.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/nonce_admission.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/payment_ambiguity.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/tests/prepared_dispatch_credentials.rs": 5,
    "crates/kernel/chio-kernel/src/kernel/tests/receipts.rs": 3,
    "crates/kernel/chio-kernel/src/kernel/tests/revocation_durability.rs": 2,
    "crates/kernel/chio-kernel/src/kernel/tests/security_dispatch.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/security_dispatch/legacy_nonce.rs": 4,
    "crates/kernel/chio-kernel/src/kernel/tests/session_reports.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/support_monetary_durability.rs": 1,
    "crates/kernel/chio-kernel/src/kernel/tests/threshold_crypto_floor.rs": 16,
    "crates/kernel/chio-kernel/src/kernel/tests/threshold_issuance.rs": 2,
    "crates/kernel/chio-kernel/src/memory_provenance.rs": 1,
    "crates/kernel/chio-kernel/src/payment.rs": 7,
    "crates/kernel/chio-kernel/src/session/tests.rs": 1,
    "crates/kernel/chio-kernel/src/threshold_approval.rs": 3,
    "crates/kernel/chio-kernel/src/tool_outcome/release/tests.rs": 29,
    "crates/kernel/chio-kernel/src/tool_outcome_tests.rs": 46,
    "crates/kernel/chio-kernel/tests/dpop.rs": 6,
    "crates/kernel/chio-kernel/tests/receipt_signing_async.rs": 1,
    "crates/kernel/chio-kernel/tests/retention.rs": 1,
    "crates/kernel/chio-kernel/tests/signer_crash.rs": 3,
    "crates/kernel/chio-kernel/tests/threshold_approval_records.rs": 8,
    "crates/kernel/chio-kernel/tests/threshold_collector_recovery.rs": 23,
    "crates/platform/chio-control-plane/src/durable_admission.rs": 5,
    "crates/platform/chio-control-plane/src/durable_admission/windows.rs": 11,
    "crates/platform/chio-control-plane/src/economic_effect_coordinator.rs": 2,
    "crates/platform/chio-control-plane/src/economic_state_anchor.rs": 11,
    "crates/platform/chio-control-plane/src/economic_state_recovery_tests.rs": 10,
    "crates/platform/chio-control-plane/src/fiscal_state_recovery.rs": 2,
    "crates/platform/chio-control-plane/src/issuance/tests/aggregate.rs": 1,
    "crates/platform/chio-control-plane/src/lib.rs": 1,
    "crates/platform/chio-control-plane/src/policy/capability_budget_tests.rs": 1,
    "crates/platform/chio-control-plane/src/policy/swarm_admission_tests.rs": 1,
    "crates/platform/chio-control-plane/src/policy/tests.rs": 2,
    "crates/platform/chio-control-plane/src/security/active_defense_host_tests.rs": 11,
    "crates/platform/chio-control-plane/src/security/active_response_authority/tests.rs": 16,
    "crates/platform/chio-control-plane/src/security/adapters/native_broker_authority_tests.rs": 11,
    "crates/platform/chio-control-plane/src/security/adapters/native_broker_capture_tests.rs": 4,
    "crates/platform/chio-control-plane/src/security/adapters/native_broker_connection_tests.rs": 2,
    "crates/platform/chio-control-plane/src/security/adapters/native_broker_live_authority_tests.rs": 4,
    "crates/platform/chio-control-plane/src/security/adapters/native_flow_caller_process_tests.rs": 3,
    "crates/platform/chio-control-plane/src/security/adapters/native_flow_caller_tests.rs": 2,
    "crates/platform/chio-control-plane/src/security/adapters/native_flow_capture_ack_tests.rs": 3,
    "crates/platform/chio-control-plane/src/security/adapters/native_flow_capture_corruption_tests.rs": 3,
    "crates/platform/chio-control-plane/src/security/adapters/native_flow_capture_tests.rs": 1,
    "crates/platform/chio-control-plane/src/security/adapters/native_flow_nonce_tests.rs": 1,
    "crates/platform/chio-control-plane/src/security/adapters/native_flow_output_fault_tests.rs": 4,
    "crates/platform/chio-control-plane/src/security/adapters/native_flow_output_preparation_tests.rs": 2,
    "crates/platform/chio-control-plane/src/security/adapters/native_flow_output_tests.rs": 6,
    "crates/platform/chio-control-plane/src/security/adapters/native_flow_process_restart.rs": 4,
    "crates/platform/chio-control-plane/src/security/adapters/native_flow_test_support.rs": 3,
    "crates/platform/chio-control-plane/src/security/adapters_parts/part_03.inc": 1,
    "crates/platform/chio-control-plane/src/security/event_consumer_parts/part_02.inc": 11,
    "crates/platform/chio-control-plane/src/security/event_consumer_parts/part_02_recovery.inc": 7,
    "crates/platform/chio-control-plane/src/security/event_consumer_parts/part_05.inc": 4,
    "crates/platform/chio-control-plane/src/security/event_consumer_parts/part_06.inc": 1,
    "crates/platform/chio-control-plane/src/security/migration_evidence.rs": 12,
    "crates/platform/chio-control-plane/src/security/scheduler_worker_parts/part_02.inc": 2,
    "crates/platform/chio-control-plane/src/security/scheduler_worker_parts/part_02_tests_tail.inc": 16,
    "crates/platform/chio-control-plane/src/trust_control/cluster_and_reports.rs": 5,
    "crates/platform/chio-control-plane/src/trust_control/config_and_public.rs": 1,
    "crates/platform/chio-control-plane/src/trust_control/finding_challenge_handlers.rs": 3,
    "crates/platform/chio-control-plane/src/trust_control/finding_hosted_profile.rs": 15,
    "crates/platform/chio-control-plane/src/trust_control/finding_operator_seller_routes.rs": 5,
    "crates/platform/chio-control-plane/src/trust_control/finding_purchase_routes/bounded_serving.rs": 6,
    "crates/platform/chio-control-plane/src/trust_control/finding_retraction_resolver.rs": 5,
    "crates/platform/chio-control-plane/src/trust_control/finding_status_handlers.rs": 3,
    "crates/platform/chio-control-plane/src/trust_control/finding_verified_fix.rs": 1,
    "crates/platform/chio-control-plane/src/trust_control/frost.rs": 1,
    "crates/platform/chio-control-plane/src/trust_control/frost/coordinator.rs": 7,
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_challenge_enforcement_e2e_tests.rs": 1,
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_challenge_enforcement_e2e_tests/status_impairment_tests.rs": 4,
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_market_exit_tests.rs": 7,
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_market_exit_tests/activation_security.rs": 5,
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_market_exit_tests/market_config.rs": 4,
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_wedge_purchase_e2e_tests.rs": 1,
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/finding_wedge_purchase_e2e_tests/status_and_settlement_tests.rs": 1,
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/remote_authority.rs": 5,
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/router_tests.rs": 1,
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/tests/retained_budget_hold.rs": 3,
    "crates/platform/chio-control-plane/src/trust_control/service_runtime/tests/structured_budget.rs": 20,
    "crates/platform/chio-control-plane/src/trust_control/service_types/cluster_budget.rs": 4,
    "crates/platform/chio-control-plane/src/trust_control/service_types/finding_market_config.rs": 19,
    "crates/platform/chio-control-plane/src/trust_control/service_types/requests.rs": 1,
    "crates/platform/chio-control-plane/src/trust_control/underwriting_and_support.rs": 1,
    "crates/platform/chio-control-plane/tests/active_defense_recovery.rs": 1,
    "crates/platform/chio-control-plane/tests/native_security_evidence.rs": 13,
    "crates/security/chio-active-response-authority/src/config/tests.rs": 8,
    "crates/security/chio-active-response-authority/src/runtime.rs": 2,
    "crates/security/chio-active-response-authority/src/store/tests.rs": 5,
    "crates/security/chio-cage/src/execution_identity.rs": 14,
    "crates/security/chio-cage/src/launch/linux_parts/part_02.rs": 5,
    "crates/security/chio-cage/src/lib_parts/part_02.rs": 3,
    "crates/security/chio-cage/tests/enforcement_evidence.rs": 24,
    "crates/security/chio-decoy/tests/watermark_vectors.rs": 2,
    "crates/security/chio-flow/src/lattice.rs": 1,
    "crates/security/chio-keyring/src/lib.rs": 11,
    "crates/security/chio-keyring/tests/checkpoint.rs": 8,
    "crates/security/chio-keyring/tests/enterprise_receipt.rs": 2,
    "crates/security/chio-keyring/tests/event.rs": 10,
    "crates/security/chio-keyring/tests/history.rs": 7,
    "crates/security/chio-keyring/tests/independent_services.rs": 10,
    "crates/security/chio-keyring/tests/router.rs": 15,
    "crates/security/chio-keyring/tests/service.rs": 9,
    "crates/security/chio-keyring/tests/sqlite.rs": 18,
    "crates/security/chio-keyring/tests/state.rs": 20,
    "crates/security/chio-keyring/tests/time.rs": 3,
    "crates/security/chio-keyring/tests/witness_sync.rs": 13,
    "crates/security/chio-quarantine/src/executor_proof.rs": 4,
    "crates/security/chio-quarantine/tests/correlation.rs": 3,
    "crates/security/chio-quarantine/tests/response_dispatch.rs": 6,
    "crates/security/chio-quarantine/tests/response_executor.rs": 19,
    "crates/security/chio-quarantine/tests/response_scheduler.rs": 1,
    "crates/security/chio-quarantine/tests/rules.rs": 1,
    "crates/security/chio-quarantine/tests/state_machine.rs": 17,
    "crates/security/chio-secret-broker/src/audit.rs": 5,
    "crates/security/chio-secret-broker/src/authority_ipc.rs": 1,
    "crates/security/chio-secret-broker/src/budget.rs": 4,
    "crates/security/chio-secret-broker/src/capability.rs": 2,
    "crates/security/chio-secret-broker/src/daemon.rs": 21,
    "crates/security/chio-secret-broker/src/daemon_runtime.rs": 2,
    "crates/security/chio-secret-broker/src/encrypted_blob_backend.rs": 9,
    "crates/security/chio-secret-broker/src/generic_https.rs": 10,
    "crates/security/chio-secret-broker/src/generic_https/rustls_transport.rs": 6,
    "crates/security/chio-secret-broker/src/inherited_fd.rs": 2,
    "crates/security/chio-secret-broker/src/ipc_client.rs": 1,
    "crates/security/chio-secret-broker/src/kernel_admission/registration.rs": 1,
    "crates/security/chio-secret-broker/src/kernel_admission/tests.rs": 10,
    "crates/security/chio-secret-broker/src/kernel_admission/tests/kernel.rs": 2,
    "crates/security/chio-secret-broker/src/kernel_admission/tests/registration.rs": 2,
    "crates/security/chio-secret-broker/src/migration.rs": 11,
    "crates/security/chio-secret-broker/src/prepared_mcp/tests.rs": 2,
    "crates/security/chio-secret-broker/src/privileged_audit.rs": 4,
    "crates/security/chio-secret-broker/src/process_boundary_tests/native.rs": 3,
    "crates/security/chio-secret-broker/src/process_boundary_tests/native_keyring.rs": 4,
    "crates/security/chio-secret-broker/src/process_boundary_tests/native_response_tests.rs": 1,
    "crates/security/chio-secret-broker/src/proof.rs": 2,
    "crates/security/chio-secret-broker/src/protocol.rs": 6,
    "crates/security/chio-secret-broker/src/reconcile.rs": 1,
    "crates/security/chio-secret-broker/src/registration.rs": 2,
    "crates/security/chio-secret-broker/src/revocation.rs": 6,
    "crates/security/chio-secret-broker/src/service_parts/tests_01_sections/cases.inc": 16,
    "crates/security/chio-secret-broker/src/service_parts/tests_02.rs": 5,
    "crates/security/chio-secret-broker/src/service_parts/tests_03.rs": 17,
    "crates/security/chio-secret-broker/src/service_parts/tests_prepared.rs": 2,
    "crates/security/chio-secret-broker/src/sqlite.rs": 1,
    "crates/security/chio-secret-broker/tests/daemon_runtime.rs": 11,
    "crates/security/chio-secret-broker/tests/execution.rs": 18,
    "crates/security/chio-secret-broker/tests/no_secret_crossing.rs": 1,
    "crates/security/chio-secret-broker/tests/production_surfaces.rs": 15,
    "crates/security/chio-secure-ipc/src/credentials.rs": 2,
    "crates/security/chio-secure-ipc/src/tests.rs": 3,
    "crates/security/chio-security-kernel/tests/adapters/security_callbacks.rs": 1,
    "crates/security/chio-security-types/src/declassification.rs": 2,
    "crates/security/chio-security-types/src/flow.rs": 19,
    "crates/security/chio-security-types/tests/capability_set_suspension.rs": 3,
    "crates/security/chio-security-types/tests/egress_restriction.rs": 4,
    "crates/security/chio-security-types/tests/event.rs": 6,
    "crates/security/chio-security-types/tests/issuance_freeze.rs": 5,
    "crates/security/chio-security-types/tests/ports_compile.rs": 9,
    "crates/security/chio-security-types/tests/response.rs": 10,
    "crates/security/chio-security-types/tests/response_dispatch.rs": 11,
    "crates/security/chio-security-types/tests/session_throttle.rs": 1,
}


RUST_NOISE = re.compile(
    r"""
      //[^\n]*                            # line comment
    | /\*                                 # block comment; nesting handled below
    | (?:b|c)?r(\#*)"                     # raw string opener, hashes captured
    | (?:b|c)?"(?:[^"\\]|(?s:\\.))*"      # string, including \<newline> continuation
    | b?'(?:(?s:\\.)|[^\\'])'             # char literal, never a lifetime
    """,
    re.VERBOSE,
)
ASSERT_CALL = re.compile(r"\bassert!\s*\(")
# A condition that says only "something failed". `matches!` and a boolean
# operator both mean the assertion says more than that, so they are not weak.
STRONGER_CONDITION = ("matches!", "&&", "||")


@dataclass(frozen=True)
class WeakAssertion:
    path: str
    line: int
    condition: str


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def discover_sources(root: Path) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            *SOURCE_PATTERNS,
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return [
        line
        for line in result.stdout.splitlines()
        if line and line.startswith(ASSERTION_ROOTS) and (root / line).is_file()
    ]


def blank_span(span: str) -> str:
    return "".join("\n" if char == "\n" else " " for char in span)


def blank_rust_noise(text: str) -> str:
    chunks: list[str] = []
    position = 0
    while True:
        match = RUST_NOISE.search(text, position)
        if match is None:
            chunks.append(text[position:])
            return "".join(chunks)
        chunks.append(text[position : match.start()])
        if match.group(0) == "/*":
            end = match.end()
            depth = 1
            while depth and end < len(text):
                opened = text.find("/*", end)
                closed = text.find("*/", end)
                if closed == -1:
                    end = len(text)
                    break
                if opened != -1 and opened < closed:
                    depth += 1
                    end = opened + 2
                else:
                    depth -= 1
                    end = closed + 2
            chunks.append(blank_span(text[match.start() : end]))
            position = end
            continue
        if match.group(1) is not None:
            terminator = '"' + match.group(1)
            end = text.find(terminator, match.end())
            end = len(text) if end == -1 else end + len(terminator)
            chunks.append(blank_span(text[match.start() : end]))
            position = end
            continue
        chunks.append(blank_span(match.group(0)))
        position = match.end()


def assertion_condition(text: str, start: int) -> tuple[str, int] | None:
    """The condition argument of an `assert!` starting at `start`, and its end."""
    depth = 1
    cursor = start
    condition_end = None
    while cursor < len(text) and depth:
        char = text[cursor]
        if char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                break
        elif char == "," and depth == 1 and condition_end is None:
            condition_end = cursor
        cursor += 1
    if depth:
        return None
    return text[start : condition_end if condition_end is not None else cursor], cursor


def weak_assertions(path: str, text: str) -> list[WeakAssertion]:
    scanned = blank_rust_noise(text)
    found: list[WeakAssertion] = []
    for match in ASSERT_CALL.finditer(scanned):
        parsed = assertion_condition(scanned, match.end())
        if parsed is None:
            continue
        condition, _ = parsed
        collapsed = " ".join(condition.split())
        if not collapsed.endswith(".is_err()"):
            continue
        if any(marker in collapsed for marker in STRONGER_CONDITION):
            continue
        found.append(
            WeakAssertion(
                path=path,
                line=scanned.count("\n", 0, match.start()) + 1,
                condition=collapsed,
            )
        )
    return found


def count_weak(root: Path, paths: list[str]) -> dict[str, list[WeakAssertion]]:
    counted: dict[str, list[WeakAssertion]] = {}
    for path in sorted(paths):
        text = (root / path).read_text(encoding="utf-8", errors="replace")
        if "is_err" not in text:
            continue
        found = weak_assertions(path, text)
        if found:
            counted[path] = found
    return counted


def validate_baseline(errors: list[str]) -> None:
    try:
        expires_on = date.fromisoformat(BASELINE_EXPIRES)
    except ValueError:
        errors.append(f"baseline expiry {BASELINE_EXPIRES!r} is not an ISO date")
        return
    if expires_on < date.today():
        errors.append(f"weak negative assertion baseline expired on {BASELINE_EXPIRES}")
    for path, cap in sorted(BASELINE.items()):
        if cap <= 0:
            errors.append(f"{path}: baseline entry is not a positive count")
        if not path.startswith(ASSERTION_ROOTS):
            errors.append(f"{path}: baseline entry is outside the gated crates")


def next_month_end(today: date) -> date:
    year, month = (
        (today.year + 1, 1) if today.month == 12 else (today.year, today.month + 1)
    )
    if month == 12:
        return date(year, 12, 31)
    return date.fromordinal(date(year, month + 1, 1).toordinal() - 1)


def ratchet_baseline(root: Path) -> int:
    counted = count_weak(root, discover_sources(root))
    kept: list[tuple[str, int]] = []
    dropped: list[str] = []
    tightened: list[str] = []
    for path, cap in BASELINE.items():
        found = counted.get(path, [])
        if not found:
            dropped.append(f"{path}: no weak negative assertions remain")
            continue
        count = min(len(found), cap)
        if count < cap:
            tightened.append(f"{path}: {cap} -> {count}")
        kept.append((path, count))
    script = Path(__file__).resolve()
    source = script.read_text(encoding="utf-8")
    expiry_marker = 'BASELINE_EXPIRES = "'
    expiry_start = source.index(expiry_marker) + len(expiry_marker)
    expiry_end = source.index('"', expiry_start)
    # Forward only. A reviewed deadline further out survives a ratchet; a
    # deadline that has arrived moves one month and the commit is the review.
    expires = max(next_month_end(date.today()).isoformat(), BASELINE_EXPIRES)
    source = source[:expiry_start] + expires + source[expiry_end:]
    start_marker = "BASELINE: dict[str, int] = {\n"
    start = source.index(start_marker) + len(start_marker)
    end = source.index("\n}\n", start)
    rendered = "".join(f'    "{path}": {count},\n' for path, count in sorted(kept))
    script.write_text(
        source[:start] + rendered.rstrip("\n") + source[end:], encoding="utf-8"
    )
    for line in dropped:
        print(f"dropped: {line}")
    for line in tightened:
        print(f"tightened: {line}")
    print(
        f"weak negative assertion baseline ratcheted: {len(kept)} files kept, "
        f"{sum(count for _, count in kept)} assertions, {len(dropped)} dropped, "
        f"{len(tightened)} tightened, expires {expires}"
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Refuse new weak negative assertions in the security crates."
    )
    parser.add_argument("--root", type=Path, default=repo_root(), help="repository root")
    parser.add_argument(
        "--ratchet",
        action="store_true",
        help=(
            "rewrite the baseline in place: re-count each file (never upward), "
            "drop files with none left, and move the expiry forward if it has "
            "arrived"
        ),
    )
    args = parser.parse_args()

    if args.ratchet:
        return ratchet_baseline(args.root.resolve())

    root = args.root.resolve()
    failures: list[str] = []
    validate_baseline(failures)

    try:
        paths = discover_sources(root)
    except subprocess.CalledProcessError as exc:
        print(f"failed to list Rust sources under {root}: {exc.stderr.strip()}", file=sys.stderr)
        return 1

    counted = count_weak(root, paths)
    total = sum(len(found) for found in counted.values())
    print(
        f"Weak negative assertions: {total} across {len(counted)} files, "
        f"baseline {sum(BASELINE.values())} across {len(BASELINE)} files, "
        f"expires {BASELINE_EXPIRES}"
    )

    for path, found in sorted(counted.items()):
        cap = BASELINE.get(path)
        if cap is None:
            failures.append(
                f"{path}: {len(found)} weak negative assertions and no baseline "
                f"entry; assert the variant that rejected "
                f"(first at {path}:{found[0].line})"
            )
            continue
        if len(found) > cap:
            failures.append(
                f"{path}: {len(found)} weak negative assertions, baseline is {cap}; "
                "assert the variant that rejected"
            )

    present = set(paths)
    for path in sorted(set(BASELINE) - set(counted)):
        if path in present:
            failures.append(
                f"{path}: no weak negative assertions remain; remove its baseline "
                "entry (run --ratchet)"
            )

    if failures:
        print("\nWeak negative assertion failures:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print("\nWeak negative assertion check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

//! Reviewed implementation coverage for the native dispatch abstractions.
//!
//! Hashing a forwarding entry point does not cover the implementation it calls.
//! Keep both identities and the shared handoff helpers in the drift gate. This
//! is a coverage contract, not a proof of refinement or transitive call coverage.

use super::{MirrorEntry, MirrorRelationship, ModelKind};

struct RequiredSource {
    path: &'static str,
    symbols: &'static [&'static str],
}

// These reviewed bodies cover extracted implementations and additional authority
// checks. Keep their callers: a forwarding wrapper cannot cover a helper body.
const EXTRACTED_IMPLEMENTATION_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/effect_obligation/recovery.rs",
        symbols: &[
            "EvidenceRecovery::acquire",
            "EvidenceRecovery::acquire_for_dispatched_child",
            "EvidenceRecovery::ensure_worker_running",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/effect_obligation/runtime.rs",
        symbols: &[
            "ChioKernel::acquire_post_effect_evidence_slot_for",
            "ChioKernel::acquire_dispatched_child_evidence_slot",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/receipt_namespace.rs",
        symbols: &[
            "ChioKernel::authenticated_receipt_namespace",
            "ChioKernel::receipt_request_namespace_digest",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/clock.rs",
        symbols: &[
            "read_fenced",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs",
        symbols: &[
            "ChioKernel::prepare_receipt_body",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/effect_obligation.rs",
        symbols: &[
            "PostEffectError",
            "PostEffectError::at",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/effect_obligation/preparation.rs",
        symbols: &[
            "DischargeBinding",
            "DischargeBinding::validate_receipt",
            "PreparedFaultReceipt::observe_fault_timestamp",
            "PreparedFaultReceipt::observe_economics",
            "PreparedFaultReceipt::observe_payment_result",
            "retain_bounded_reference",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery.rs",
        symbols: &[
            "ChioKernel::terminalize_dispatch_committed_admission",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/credential_reservation.rs",
        symbols: &["DispatchCredentialReservation::commit_approval_marker"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/credential_reservation/preparation.rs",
        symbols: &["PreparedDispatchCredentials::valid_until_unix_ms"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/tool_outcome.rs",
        symbols: &[
            "RawInvocationOutcomeV1::from_canonical_bytes",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/tool_outcome/original_security_dispatch.rs",
        symbols: &["RawInvocationOutcomeV1::from_persisted_fields"],
    },
    RequiredSource {
        path: "crates/security/chio-flow/src/engine.rs",
        symbols: &[
            "ResolvedFlowRequest::source_label",
            "ResolvedFlowRequest::input_taint_transition",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/caller.rs",
        symbols: &["ChioKernel::frame_caller_return_context_with_native"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/caller/deadline.rs",
        symbols: &[
            "ChioKernel::freeze_caller_start_deadline",
            "CallerReturnWire::valid_deadline_shape",
            "CallerReturnWire::start_deadline",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/egress/record.rs",
        symbols: &["Record::validate_initialized", "load_inner", "load_initialized", "load_operation_inner"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/egress/readback/portable.rs",
        symbols: &["load_history_initialized"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/record.rs",
        symbols: &["Record::validate_initialized"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/capture.rs",
        symbols: &["verify_capture_attachment_initialized"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/nonce_preflight/record.rs",
        symbols: &["Record::validate_initialized", "load_inner", "load_initialized"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/output/record.rs",
        symbols: &["Record::validate_initialized", "load_inner", "load_initialized"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/output/declassification.rs",
        symbols: &["expected_initialized"],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/native_flow/output.rs",
        symbols: &["classification_payload"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/tool_outcome_store.rs",
        symbols: &[
            "verify_tool_outcome_data_invariants",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/history/ordered.rs",
        symbols: &[
            "family_head",
            "segment_totals",
            "join_precedes",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/checkpoint.rs",
        symbols: &[
            "latest",
            "floors",
            "visit_rows",
            "verify_all",
            "verify_coverage",
            "projection_reference",
            "SqliteAdmissionOperationStore::checkpoint_history",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/checkpoint/record.rs",
        symbols: &[
            "FORMAT",
            "DELTA_FORMAT",
            "Record",
            "Record::format",
            "Record::bytes",
            "Record::validate",
            "load_local",
            "latest",
            "verify_reference",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/checkpoint/rows.rs",
        symbols: &[
            "Fingerprint",
            "fingerprint",
            "Current::fingerprints",
            "read",
            "write",
            "stored",
            "keyframe",
            "added",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/checkpoint/delta.rs",
        symbols: &[
            "READ_FACTOR",
            "MAX_TOMBSTONES",
            "Tombstone",
            "Delta",
            "Delta::validate",
            "within_budget",
            "charge",
            "added_digest",
            "Image",
            "Image::insert",
            "Image::remove",
            "Image::verify",
            "Chain",
            "Chain::start",
            "Chain::apply",
            "image",
            "plan",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/checkpoint/schema.rs",
        symbols: &[
            "sql",
            "verify_catalog",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/capture.rs",
        symbols: &[
            "NativeSecurityDispatchCaptureAuthority::retain_for_capture",
            "NativeSecurityDispatchCaptureAuthority::retain_once",
            "NativeSecurityDispatchCaptureAuthority::classify_failure",
            "NativeSecurityDispatchCaptureAuthority::holds_committed_egress",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/ledger.rs",
        symbols: &[
            "PreparedNativeSecurityEgress::validate_retention_input",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/native_dispatch_binding.rs",
        symbols: &[
            "NATIVE_DISPATCH_LEDGER_SCHEMA",
            "NATIVE_DISPATCH_LEDGER_LEGACY_SCHEMA",
            "NativeSecurityDispatchRequestBindingV1::from_live_request",
            "NativeSecurityDispatchRequestBindingV1::from_ledger",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/capture.rs",
        symbols: &[
            "verify_capture_record",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/tool_outcome_projection.rs",
        symbols: &[
            "load_projection_artifacts",
            "load_verified_projection_with_retained_inputs",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/return_binding.rs",
        symbols: &[
            "SqliteAdmissionOperationStore::verify_original_native_return_tx",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/integrity.rs",
        symbols: &[
            "verify_event_reference",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/history_scope.rs",
        symbols: &[
            "CheckedHistoryScope",
            "CheckedHistoryScope::qualify",
            "CheckedHistoryScope::require_connection",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/projection.rs",
        symbols: &[
            "verify_stored_terminal_projection_with_history",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/recovery.rs",
        symbols: &[
            "verify_all",
            "verify_outcome_recovery_status",
            "SqliteAdmissionOperationStore::persist_recovery_deferral",
            "SqliteAdmissionOperationStore::persist_recovery_deferral_clear",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/threshold_approval/nonce_capture.rs",
        symbols: &[
            "reserved_nonce_capture_approval",
            "ReservedThresholdApproval::binds",
            "ReservedThresholdApproval::validate_at",
            "nonce_verification_time_unix_ms",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/financial_receipt.rs",
        symbols: &[
            "ChioKernel::validate_retained_financial_receipt",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/payment_pricing.rs",
        symbols: &[
            "payment_cost_breakdown",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery/page.rs",
        symbols: &[
            "ChioKernel::reconcile_admission_recovery_page",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/recovery/operation.rs",
        symbols: &[
            "ChioKernel::recover_one_admission",
        ],
    },

    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/budget_store/composite/transitions/capture.rs",
        symbols: &[
            "SqliteBudgetStore::capture_composite_invocation_with_diagnostic",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/policy.rs",
        symbols: &[
            "Policy::validate_current_for_capture",
            "Policy::validate_at_for_capture",
        ],
    },

];

// The cancellation model covers only clean pre-dispatch snapshots. The live
// effect-boundary anchor records the handoff, not a post-effect proof.
const CANCELLATION_BOUNDARY_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs",
        symbols: &[
            "PostAdmissionDropGuard",
            "PostAdmissionDropGuard::new",
            "PostAdmissionDropGuard::disarm",
            "PostAdmissionDropGuard::handle_pre_dispatch_drop",
            "PostAdmissionDropGuard::record_pre_dispatch_cleanup_fault_receipt",
            "PostAdmissionDropGuard::drop",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/effect_obligation.rs",
        symbols: &["PostEffectObligation::enter"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/validation.rs",
        symbols: &["ChioKernel::reverse_pre_execution_budget_mutation"],
    },
];

const DROP_CONSTRUCTION_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/kernel_drop_guard.rs",
        symbols: &[
            "PostAdmissionDropGuard::record_pre_dispatch_cleanup_fault_receipt",
            "PostAdmissionDropGuard::drop",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/clock.rs",
        symbols: &[
            "read",
            "ChioKernel::read_authority_time",
            "ChioKernel::trusted_now_millis",
        ],
    },
];

const NATIVE_LIFECYCLE_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/mod.rs",
        symbols: &["SecurityPreDispatchHook"],
    },
    RequiredSource {
        path:
            "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/lifecycle.rs",
        symbols: &[
            "CapturedLifecycle",
            "CapturedLifecycle::finish",
            "NativeReleaseOwner",
            "NativeReleaseOwner::ensure_final_release",
            "NativeReleaseOwner::ensure_final_release_with_output",
            "ChioKernel::freeze_and_commit_evaluation_dispatch",
            "policy_deadline",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/capture.rs",
        symbols: &["NativeSecurityDispatchCaptureAuthority::capture_once"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/credential_reservation/native_dispatch.rs",
        symbols: &["VerifiedNativeDispatchCredentials::valid_until_unix_ms"],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/native_flow.rs",
        symbols: &[
            "NativeFlowResolver::with_captured_lifecycle",
            "NativeFlowResolver::supports_native_dispatch",
            "NativeFlowResolver::commit_native_dispatch",
        ],
    },
];

const REQUIRED_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/session_ops/nested_tool_call.rs",
        symbols: &[
            "NestedToolCallProofs",
            "ChioKernel::evaluate_tool_call_operation_with_nested_flow_client",
            "ChioKernel::evaluate_tool_call_operation_with_nested_flow_client_async",
            "ChioKernel::evaluate_tool_call_operation_with_nested_flow_client_and_proofs",
            "ChioKernel::evaluate_tool_call_operation_with_nested_flow_client_and_proofs_async",
            "nested_tool_request",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/dpop_acquisition.rs",
        symbols: &[
            "ChioKernel::set_operation_owned_dpop_authority",
            "ChioKernel::verify_dpop_activation",
            "ChioKernel::verify_operation_owned_dpop",
            "ChioKernel::claim_prepared_dpop",
            "ChioKernel::verify_owned_dpop",
            "ChioKernel::release_operation_owned_dpop_before_dispatch",
            "ChioKernel::release_exact_dpop_reservation",
            "ChioKernel::claim_dpop_recovery",
            "reservation_phase",
            "acquisition_phase",
            "load_history",
            "validate_successor",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/dpop_custody.rs",
        symbols: &[
            "ChioKernel::release_retained_dpop",
            "store_call",
            "load_exact_history",
            "validate_recovery_history",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/dispatch/dpop_verification.rs",
        symbols: &["ChioKernel::verify_dpop_for_permission_preview"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/evaluation/async_evaluation_core.rs",
        symbols: &["ChioKernel::evaluate_tool_call_async_with_session_context_scoped"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/evaluation/evaluation_entry.rs",
        symbols: &["ChioKernel::evaluate_tool_call_async_with_session_context"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/evaluation/nested_flow_evaluation.rs",
        symbols: &[
            "ChioKernel::evaluate_tool_call_with_nested_flow_client_async",
            "ChioKernel::evaluate_tool_call_with_nested_flow_client_async_and_security_context",
            "ChioKernel::evaluate_tool_call_with_nested_flow_client_async_scoped",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/evaluation/delivery_preparation.rs",
        symbols: &["ChioKernel::wait_for_tool_dispatch_readiness"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/credential_reservation.rs",
        symbols: &[
            "ExecutionNonceCredential",
            "ExecutionNonceCredential::for_dispatch",
            "DispatchCredentialReservation::requires_post_reservation_revalidation",
            "run_credential_store_operation",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/credential_reservation/preparation.rs",
        symbols: &[
            "CredentialPreparationInput",
            "PreparedDispatchCredentials",
            "PreparedDispatchCredentials::refresh",
            "PreparedDispatchCredentials::validate_origin",
            "PreparedDispatchCredentials::approval_credential",
            "PreparedDispatchCredentials::dpop_credential",
            "ChioKernel::prepare_dispatch_credentials",
            "ChioKernel::prepare_credentials",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/credential_reservation/acquisition.rs",
        symbols: &["PreparedDispatchCredentials::reserve_checked"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/credential_reservation/operation_owned.rs",
        symbols: &[
            "ChioKernel::run_pre_budget_admission",
            "ChioKernel::reserve_admitted_dispatch_credentials",
            "ChioKernel::reserve_admitted_caller_credentials",
            "PreparedDispatchCredentials::claim_for_admission",
            "PreparedDispatchCredentials::reserve_for_admission",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/governed_acquisition.rs",
        symbols: &[
            "ChioKernel::claim_prepared_governed_approval",
            "ChioKernel::verify_owned_governed_approval",
            "ChioKernel::release_exact_governed_approval_reservation",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/dispatch.rs",
        symbols: &[
            "ChioKernel::wait_for_runtime_admission_dispatch_readiness",
            "ChioKernel::revalidate_immediately_before_dispatch",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/nonce_admission.rs",
        symbols: &["ChioKernel::validate_execution_nonce_non_consuming"],
    },
];

const REVOCATION_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/effect_obligation.rs",
        symbols: &["PostEffectObligation::commit_terminal_receipt"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/validation/revocation_trace.rs",
        symbols: &["ChioKernel::revoke_capability"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/construction.rs",
        symbols: &["ChioKernel::lock_runtime_trace_transition"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs",
        symbols: &[
            "ChioKernel::record_chio_receipt",
            "ChioKernel::record_chio_receipt_with_federation",
            "ChioKernel::append_terminal_receipt_during_trace_transition",
        ],
    },
];

const CALLER_SHARE_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/validation.rs",
        symbols: &["ChioKernel::admit_capability_budget"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/validation/caller_budget.rs",
        symbols: &["ChioKernel::admit_capability_budget_for_dispatch"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/caller_budget.rs",
        symbols: &["ChioKernel::load_durable_caller_budget_shares"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/caller_budget.rs",
        symbols: &[
            "AdmissionCallerBudgetShare",
            "AdmissionCallerBudgetShare::is_owned_by",
            "AdmissionCallerBudgetShare::from_retained_operation",
            "AdmissionCallerBudgetShare::is_reserved_for_caller",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/caller_budget.rs",
        symbols: &["SqliteAdmissionOperationStore::caller_budget_shares"],
    },
];

const DISPATCH_COMMIT_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/effect_obligation.rs",
        symbols: &[
            "PostEffectInputs",
            "PostEffectObligation::enter",
            "PostEffectObligation::commit_terminal_receipt",
            "PostEffectObligation::fail",
            "PostEffectObligation::drop",
            "Discharged::deliver",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/effect_obligation/post_effect.rs",
        symbols: &["record_durable_return"],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/flow_dispatch.rs",
        symbols: &[
            "PreparedFlowDispatch",
            "PreparedFlowDispatch::live_request_digest",
            "PreparedFlowDispatch::validate_live_request",
            "PreparedFlowDispatch::commit",
            "PreparedFlowDispatch::validate_current",
            "PersistentFlowResolver::prepare_dispatch",
            "PersistentFlowResolver::commit_dispatch",
            "PersistentFlowResolver::commit_dispatch_with_evidence",
            "PersistentFlowResolver::commit_admission_at",
            "PersistentFlowResolver::persist_dispatch_failed_evidence",
            "live_request_digest",
        ],
    },
    RequiredSource {
        path: "crates/security/chio-flow/src/engine.rs",
        symbols: &[
            "PreparedFlowAdmission",
            "PreparedFlowAdmission::declassification",
            "PreparedFlowAdmission::into_admission",
            "PreparedFlowAdmission::consume_declassification",
            "PreparedFlowAdmission::consume_declassification_at",
            "prepare_pre_invocation",
            "evaluate_pre_invocation",
            "evaluate_pre_invocation_with_declassification",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/security_release.rs",
        symbols: &[
            "DurableSecurityReleaseInput",
            "recovery_required",
            "ChioKernel::verify_durable_security_release",
            "ChioKernel::require_durable_security_release",
            "ChioKernel::complete_durable_security_release",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal_recovery.rs",
        symbols: &[
            "ChioKernel::recover_durable_tool_admission",
            "ChioKernel::finalize_durable_tool_return",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal.rs",
        symbols: &[
            "ChioKernel::completed_durable_tool_response",
            "ChioKernel::validate_completed_durable_receipt",
            "ChioKernel::finalize_durable_tool_return_with_security_release",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/record_return.rs",
        symbols: &["ChioKernel::record_durable_tool_return"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/terminal/evaluation_contract.rs",
        symbols: &["ChioKernel::durable_evaluation_contract"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/tool_outcome/security_release.rs",
        symbols: &[
            "SecurityReleaseRecordV1",
            "AcknowledgedSecurityReleaseV1",
            "AcknowledgedSecurityReleaseV1::acknowledge",
            "AcknowledgedSecurityReleaseV1::record", "SecurityReleaseRecordV1::pending",
            "SecurityReleaseRecordV1::canonical_bytes",
            "SecurityReleaseRecordV1::from_canonical_bytes",
            "SecurityReleaseRecordV1::validate_against",
            "SecurityReleaseRecordV1::validate_retained_against",
            "RawInvocationOutcomeV1::security_dispatch_commitment_id",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/tool_outcome.rs",
        symbols: &[
            "RawInvocationOutcomeV1",
            "PersistedRawInvocationOutcomeV1",
            "RawInvocationContext",
            "required_option",
            "RawInvocationOutcomeV1::from_committed_dispatch",
            "RawInvocationOutcomeV1::from_persisted",
            "RawInvocationOutcomeV1::to_persisted",
            "RawInvocationOutcomeV1::canonical_blob_bounded",
            "RawInvocationOutcomeV1::requires_security_release",
            "ToolOutcomeStore",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/tool_outcome/receipt_signing.rs",
        symbols: &[
            "FrozenReceiptSigningIdentityV1",
            "FrozenReceiptSigningIdentityV1::new",
            "FrozenReceiptSigningIdentityV1::validate",
            "FrozenReceiptSigningIdentityV1::public_key",
            "FrozenReceiptSigningIdentityV1::crypto_floor",
            "RawInvocationOutcomeV1::receipt_signing_identity",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/signing_authority.rs",
        symbols: &[
            "ChioKernel::freeze_receipt_signing_identity",
            "ChioKernel::require_original_receipt_signer",
        ],
    },
    RequiredSource {
        path: "crates/core/chio-core-types/src/receipt/body.rs",
        symbols: &["ChioReceipt::sign_with_backend"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/responses/receipt_persistence.rs",
        symbols: &[
            "ChioKernel::build_and_sign_receipt_for_identity",
            "ChioKernel::build_and_sign_receipt_with_authority",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/tool_outcome_security_release.rs",
        symbols: &[
            "has_release_namespace",
            "verify_unstamped_source",
            "participant_digest",
            "load",
            "verify_projection",
            "require_terminal_release",
            "SqliteToolOutcomeStore::persist_security_release",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/tool_outcome_store.rs",
        symbols: &[
            "SqliteToolOutcomeStore::require_security_release_checkpoint_support",
            "SqliteToolOutcomeStore::record_security_release",
            "SqliteToolOutcomeStore::lookup_security_release",
            "initialize_tool_outcome_schema",
            "preflight_tool_outcome_schema",
            "verify_tool_outcome_schema_catalog",
            "verify_tool_outcome_invariants",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/tool_outcome_projection.rs",
        symbols: &[
            "VerifiedProjection",
            "verify_outcome_projection",
            "load_verified_projection",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/security_dispatch.rs",
        symbols: &[
            "callback",
            "record_outcome",
            "SecurityDispatchOutcomeHandle::new",
            "SecurityDispatchOutcomeHandle::mark_dispatch_started",
            "SecurityDispatchOutcomeHandle::record",
            "SecurityDispatchOutcomeHandle::record_released",
            "SecurityDispatchOutcomeHandle::record_dispatch_failed",
            "SecurityDispatchOutcomeHandle::record_outcome_unknown_after_dispatch",
            "SecurityDispatchOutcomeHandle::drop",
            "SecurityDispatchOutcomeHandle::validate_context",
            "SecurityRequestLifecycleHandle",
            "SecurityRequestLifecycleHandle::new",
            "SecurityRequestLifecycleHandle::ensure_final_release",
            "SecurityRequestLifecycleHandle::ensure_final_release_for", "SecurityRequestLifecycleHandle::validate_release_context",
            "SecurityRequestLifecycleHandle::drop",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/dispatch/security_pre_dispatch.rs",
        symbols: &[
            "derive_security_dispatch_commitment_id",
            "security_pre_dispatch_denial",
            "ChioKernel::run_security_pre_dispatch_hook",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/evaluation/caller_execution.rs",
        symbols: &[
            "ChioKernel::caller_reservation_profile_denial",
            "ChioKernel::reserve_caller_execution_blocking",
            "ChioKernel::finish_caller_reservation",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/credential_reservation.rs",
        symbols: &["DispatchCredentialReservation::rollback_entries"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/caller.rs",
        symbols: &[
            "CallerReturnWire",
            "ChioKernel::frame_caller_return_context",
            "ChioKernel::restore_caller_return_context",
            "ChioKernel::decode_caller_return_context",
            "ChioKernel::decode_caller_return_payload",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/native_caller_custody.rs",
        symbols: &["CALLER_RETURN_CONTEXT_SCHEMA", "AdmissionCallerDispatchContextV1::native_release_custody"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator.rs",
        symbols: &["ChioKernel::capture_and_commit_durable_dispatch"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/federation_context.rs",
        symbols: &[
            "ChioKernel::restore_frozen_federation_return_context",
            "ChioKernel::decode_retained_federation_context",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context.rs",
        symbols: &[
            "DurableDispatchCommitError",
            "ChioKernel::freeze_and_commit_durable_dispatch",
            "ChioKernel::freeze_durable_tool_return_context",
            "DurableToolReturnContext",
            "DurableToolReturnContext::validate_binding",
            "DurableToolReturnContext::bind_native_dispatch",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/return_context/participants.rs",
        symbols: &[
            "FrozenDispatchParticipants",
            "FrozenDispatchParticipants::from_operation",
            "FrozenDispatchParticipants::validate",
            "FrozenDispatchParticipants::bind_native_dispatch",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/evaluation/dispatch_commit_failure.rs",
        symbols: &["ChioKernel::build_durable_dispatch_failure_response", "ChioKernel::build_pre_commit_credential_rejection_response"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/credential_reservation.rs",
        symbols: &[
            "DispatchCredentialReservation",
            "DispatchCredentialReservation::rollback_before_dispatch",
            "DispatchCredentialReservation::rollback_before_dispatch_with_disposition",
            "DispatchCredentialReservation::retain_if_dropped",
            "DispatchCredentialReservation::retain_after_external_authorization",
            "DispatchCredentialReservation::retention_disposition",
            "DispatchCredentialReservation::commit",
            "DispatchCredentialReservation::drop",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/execution_nonce.rs",
        symbols: &["ExecutionNonceStore"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/execution_nonce/store.rs",
        symbols: &[
            "InMemoryExecutionNonceStore",
            "State",
            "Entry",
            "InMemoryExecutionNonceStore::reserve_signed",
            "InMemoryExecutionNonceStore::reserve_until",
            "InMemoryExecutionNonceStore::reserve_for_dispatch",
            "InMemoryExecutionNonceStore::rollback_dispatch_reservation",
            "InMemoryExecutionNonceStore::is_consumed",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/execution_nonce_store.rs",
        symbols: &[
            "SqliteExecutionNonceStore",
            "RETENTION_GRACE_SECS",
            "SqliteExecutionNonceStore::reserve_until",
            "SqliteExecutionNonceStore::reserve_for_dispatch",
            "SqliteExecutionNonceStore::try_reserve_signed_entry",
            "SqliteExecutionNonceStore::try_reserve_entry_with_clock_policy",
            "SqliteExecutionNonceStore::validate_observed_clock",
            "record_execution_nonce_prune",
            "SqliteExecutionNonceStore::rollback_dispatch_reservation",
            "SqliteExecutionNonceStore::is_consumed",
        ],
    },
];

const RUNTIME_PREPARATION_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-runtime-core/src/admission.rs",
        symbols: &[
            "RuntimeAdmissionReservationTracker",
            "evaluate_runtime_admission_tracked",
            "commit_prepared_runtime_admission",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-runtime-core/src/admission/preparation.rs",
        symbols: &[
            "RuntimeAdmissionPreparation",
            "PreparedRuntimeAdmission",
            "prepare_runtime_admission",
            "prepare_runtime_admission_from_bundle",
            "prepare_with_bundle_loader",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-runtime-core/src/admission_hook.rs",
        symbols: &[
            "ChioRuntimeAdmissionHook::evaluate",
            "ChioRuntimeAdmissionHook::release_reservations",
            "ChioRuntimeAdmissionHook::release_reserved",
            "ChioRuntimeAdmissionHook::admission_time",
            "ChioRuntimeAdmissionHook::runtime_participant_binding",
            "ChioRuntimeAdmissionHook::evaluate_operation_owned",
            "ChioRuntimeAdmissionHook::revalidate_admitted_request",
            "ChioRuntimeAdmissionHook::revalidate_before_dispatch",
            "ChioRuntimeAdmissionHook::revalidate_operation_owned_before_dispatch",
            "ChioRuntimeAdmissionHook::revalidate_operation_owned_for_native_capture",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-runtime-core/src/admission_hook/preparation.rs",
        symbols: &[
            "HookAdmissionPreparation",
            "PreparedHookAdmission",
            "ChioRuntimeAdmissionHook::prepare_request",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-runtime-core/src/admission_hook/reservation.rs",
        symbols: &["PreparedHookAdmission::reserve"],
    },
    RequiredSource {
        path: "crates/kernel/chio-runtime-core/src/admission_hook/treaty_evidence.rs",
        symbols: &[
            "verify_treaty_reference_from_store",
            "verified_federation_treaty_material",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-runtime-core/src/admission_hook/swarm_authority.rs",
        symbols: &["verify_swarm_authority_reference"],
    },
];

const RUNTIME_OWNERSHIP_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/dpop_replay/integrity.rs",
        symbols: &["verify_dpop_replay_projection_coverage", "verified_projection_records"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/dpop_replay/custody.rs",
        symbols: &["require_active_authority"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/dpop_claim/records.rs",
        symbols: &["load"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/native_flow_join.rs",
        symbols: &["NativeSecurityFlowJoinRecordV1"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/store.rs",
        symbols: &["AdmissionOperationStore", "QualifiedAdmissionOperationStoreExt"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_acquisition.rs",
        symbols: &["NativeSecurityFlowJoinAuthority", "NativeSecurityFlowJoinAuthority::binding", "NativeSecurityFlowJoinAuthority::join", "NativeSecurityFlowJoinAuthority::join_once", "NativeSecurityFlowJoinAuthority::read_history", "NativeSecurityFlowJoinAuthority::finish", "ChioKernel::run_native_admission_preparation", "store_call"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/store.rs",
        symbols: &["SqliteAdmissionOperationStore::join_native_security_flow", "SqliteAdmissionOperationStore::load_native_security_flow_join"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/readback.rs",
        symbols: &["SqliteAdmissionOperationStore::load_native_flow_join_record"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator.rs",
        symbols: &[
            "ChioKernel::begin_durable_tool_admission_for_transport",
            "ChioKernel::native_security_authority_binding",
            "immutable_tool_admission_request_hash",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/runtime_participant.rs",
        symbols: &[
            "SqliteAdmissionOperationStore::claim_runtime_participants",
            "require_intent",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/governed_approval_claim.rs",
        symbols: &[
            "SqliteAdmissionOperationStore::claim_governed_approval",
            "require_intent",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/dpop_claim.rs",
        symbols: &[
            "SqliteAdmissionOperationStore::claim_dpop_replay",
            "require_intent",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/mutations.rs",
        symbols: &[
            "SqliteAdmissionOperationStore::join_security_participant_flow",
            "require_request",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/governed_acquisition.rs",
        symbols: &["ChioKernel::configured_governed_approval_binding"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/authority_profile.rs",
        symbols: &[
            "AdmissionAuthoritySelectionV1",
            "AdmissionAuthorityProfileV1",
            "Wire",
            "required_option",
            "AdmissionAuthorityProfileV1::try_from",
            "AdmissionAuthorityProfileV1::new",
            "AdmissionAuthorityProfileV1::runtime",
            "AdmissionAuthorityProfileV1::approval",
            "AdmissionAuthorityProfileV1::dpop",
            "AdmissionAuthorityProfileV1::has_operation_owned_authority",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/retained_request.rs",
        symbols: &[
            "RetainedToolAdmissionRequestV1",
            "RetainedRequestWire",
            "immutable_tool_request_hash",
            "RetainedToolAdmissionRequestV1::from_admission",
            "RetainedToolAdmissionRequestV1::from_canonical_bytes",
            "RetainedToolAdmissionRequestV1::request_without_transient_credentials",
            "SCHEMA",
            "RetainedToolAdmissionRequestV1::authority_profile",
            "RetainedToolAdmissionRequestV1::security_binding",
            "RetainedToolAdmissionRequestV1::native_security_authority_binding",
            "RetainedToolAdmissionRequestV1::validate_binding",
            "RetainedToolAdmissionRequestV1::validate_request_material",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/retained_request/security_binding.rs",
        symbols: &[
            "AdmissionSecurityBindingV1",
            "StableSecurityContextV1",
            "AdmissionSecurityBindingV1::native_authority",
            "AdmissionSecurityBindingV1::from_trusted_selection",
            "AdmissionSecurityBindingV1::validate",
            "AdmissionSecurityBindingV1::matches_requirements",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/authority_profile.rs",
        symbols: &[
            "ChioKernel::load_original_request_for_finalization",
            "ChioKernel::admission_authority_profile",
            "ChioKernel::validate_original_authority_profile",
            "ChioKernel::validate_live_admission_authority_profile",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/runtime_acquisition.rs",
        symbols: &[
            "RuntimeParticipantClaimAuthority",
            "RuntimeParticipantClaimAuthority::claim",
            "RuntimeParticipantClaimAuthority::claim_once",
            "RuntimeParticipantClaimAuthority::finish",
            "ChioKernel::evaluate_operation_owned_runtime_hook",
            "ChioKernel::revalidate_operation_owned_runtime_hook",
            "ChioKernel::release_operation_owned_runtime_before_dispatch",
            "load_history",
            "validate_claim_successor",
            "require_claim",
        "ChioKernel::runtime_revalidation_source", ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/runtime_participant.rs",
        symbols: &[
            "store_call",
            "ChioKernel::release_retained_runtime_participants",
            "load_exact_history",
            "validate_recovery_history",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/dispatch/runtime_admission.rs",
        symbols: &[
            "ChioKernel::configured_runtime_participant_binding",
            "ChioKernel::run_runtime_admission_hook",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-runtime-core/src/admission/operation_owned.rs",
        symbols: &[
            "PreparedRuntimeAdmission::destructive_resource",
            "PreparedRuntimeAdmission::commit_operation_owned",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-runtime-core/src/admission_hook/operation_owned.rs",
        symbols: &[
            "PreparedHookAdmission::reserve_operation_owned",
            "verify_revalidation_material",
        "PreparedHookAdmission::verify_owned_dispatch", "PreparedHookAdmission::operation_owned_resources", "PreparedHookAdmission::operation_owned_plan_digest", ],
    },
];

const NATIVE_CAPTURE_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/runtime_admission.rs",
        symbols: &["RuntimeAdmissionHook"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/runtime_participant.rs",
        symbols: &[
            "RuntimeDispatchValidity",
            "RuntimeDispatchValidity::new",
            "RuntimeDispatchValidity::validate_at",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-runtime/src/admission_hook.rs",
        symbols: &[
            "ChioRuntimeAdmissionHook::core_hook",
            "ChioRuntimeAdmissionHook::revalidate_operation_owned_for_native_capture",
        ],
    },
    RequiredSource {
        path: "crates/kernel/chio-runtime-core/src/admission_hook/dispatch_validity.rs",
        symbols: &[
            "ChioRuntimeAdmissionHook::native_dispatch_validity",
            "ChioRuntimeAdmissionHook::selected_key_deadline",
        ],
    },
    RequiredSource {
        path:
            "crates/platform/chio-store-sqlite/src/admission_operation_store/security_dispatch.rs",
        symbols: &[
            "verify_native_security_dispatch_tx",
            "verify_dispatch_capture_owner_tx",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/budget_store/composite/transitions/capture.rs",
        symbols: &["SqliteBudgetStore::capture_composite_invocation_inner"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/store.rs",
        symbols: &["SqliteAdmissionOperationStore::compare_and_swap"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/participant.rs",
        symbols: &["advance_named_participant_tx"],
    },
];

// Preflight phase and physical journal are source-drift anchors only, not
// new proofs of nonce execution, SQLite isolation or crash safety.
const NATIVE_NONCE_PREFLIGHT_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/nonce_preflight/issuance.rs",
        symbols: &["require_preflight_for_issuance"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/execution_nonce/issuance.rs",
        symbols: &["SqliteAdmissionOperationStore::issue_nonce"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/native_input_join.rs",
        symbols: &["InputJoinPhase","NativeSecurityInputJoinRequestV1::for_phase","NativeSecurityInputJoinRequestV1::validate_phase","NativeSecurityInputJoinRequestV1::validate_phase_resolution"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/native_nonce_preflight.rs",
        symbols: &["NativeSecurityNoncePreflightJoinRequestV1","NativeSecurityNoncePreflightJoinRecordV1","NativeSecurityNoncePreflightJoinRequestV1::new","NativeSecurityNoncePreflightJoinRequestV1::validate","NativeSecurityNoncePreflightJoinRequestV1::validate_resolution","NativeSecurityNoncePreflightJoinRecordV1::validate"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_acquisition.rs",
        symbols: &["NativeSecurityFlowJoinAuthority::finish_with"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_acquisition/nonce_preflight.rs",
        symbols: &["NativeSecurityNoncePreflightJoinAuthority","NativeSecurityNoncePreflightJoinAuthority::finish","NativeSecurityNoncePreflightJoinAuthority::join_input","ChioKernel::run_native_nonce_preflight_preparation"],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/native_flow.rs",
        symbols: &["NativeFlowResolver::classify_admission_input","NativeFlowResolver::prepare_native_nonce_preflight"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/store.rs",
        symbols: &["SqliteAdmissionOperationStore::join_native_security_nonce_preflight","SqliteAdmissionOperationStore::load_native_security_nonce_preflight_join"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/security_state/native_mutation.rs",
        symbols: &["join_native_nonce_preflight","JoinAuthorization"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/nonce_preflight.rs",
        symbols: &["NativeNoncePreflightJoinAuthority","projection_reference","checkpoint"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/nonce_preflight/contract.rs",
        symbols: &["require_original"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/nonce_preflight/write.rs",
        symbols: &["SqliteAdmissionOperationStore::join_security_participant_nonce_preflight","SqliteAdmissionOperationStore::load_native_nonce_preflight_join_record","footprint"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/nonce_preflight/record.rs",
        symbols: &["FORMAT","Record","Record::bytes","Record::digest","Record::evidence","Record::validate","Record::insert","head","load","load_operation"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/nonce_preflight/schema.rs",
        symbols: &["sql","exists","catalog","verify_catalog"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/nonce_preflight/integrity.rs",
        symbols: &["verify_coverage"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/history/rows.rs",
        symbols: &["verify_rows","apply_image"],
    },
];

const NATIVE_INPUT_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_acquisition.rs",
        symbols: &["NativeSecurityFlowJoinAuthority::key", "NativeSecurityFlowJoinAuthority::attempt", "NativeSecurityFlowJoinAuthority::with_join_custody", "NativeSecurityFlowJoinAuthority::confirm"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/mutations.rs",
        symbols: &["SqliteAdmissionOperationStore::join_security_participant_input", "SqliteAdmissionOperationStore::join_native_command"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/store.rs",
        symbols: &["SqliteAdmissionOperationStore::join_native_security_input", "SqliteAdmissionOperationStore::load_native_security_input_join"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/readback.rs",
        symbols: &["SqliteAdmissionOperationStore::load_native_input_join_record", "SqliteAdmissionOperationStore::load_native_join_record"],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/flow_policy.rs",
        symbols: &["FlowPolicyView::classified_input_label", "FlowPolicyView::classify_arguments"],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/native_flow.rs",
        symbols: &["NativeFlowResolver::name", "NativeFlowResolver::native_authority_binding", "NativeFlowResolver::prepare_native_admission", "NativeFlowResolver::prepare_native_output", "NativeFlowResolver::commit"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/native_input_join.rs",
        symbols: &["NativeSecurityInputJoinRequestV1", "NativeSecurityInputJoinRecordV1", "NativeSecurityInputJoinRequestV1::new", "NativeSecurityInputJoinRequestV1::operation_id", "NativeSecurityInputJoinRequestV1::key", "NativeSecurityInputJoinRequestV1::input_label", "NativeSecurityInputJoinRequestV1::transition_id", "NativeSecurityInputJoinRequestV1::validate", "NativeSecurityInputJoinRequestV1::validate_resolution", "NativeSecurityInputJoinRecordV1::validate", "transition_id"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_acquisition/input.rs",
        symbols: &["NativeSecurityFlowJoinAuthority::join_input"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/security_state/flow_state/input_join.rs",
        symbols: &["resolve_native_input_join"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/mutations/command.rs",
        symbols: &["Command", "Command::key", "Command::transition_id", "Command::input", "Command::validate", "Command::matches", "Command::resolve"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/history.rs",
        symbols: &["Record", "FORMAT", "INPUT_FORMAT", "MAX_RECORD_BYTES", "Record::join_record", "Record::input_record", "Record::bytes", "Record::digest", "Record::validate", "Record::insert", "format", "load", "head", "load_for_operation"],
    },
];

const NATIVE_POLICY_EVIDENCE_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress.rs",
        symbols: &[
            "PreparedNativeSecurityEgress::operation_version",
            "PreparedNativeSecurityEgress::retained_request_digest",
            "PreparedNativeSecurityEgress::kernel_policy_hash",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/flow_policy.rs",
        symbols: &[
            "ResolvedFlowPolicy",
            "FlowPolicyView::resolve_pre_with_evidence",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/native_flow.rs",
        symbols: &[
            "PreparedNativeFlowDispatch::policy_evidence",
            "NativeFlowCustody::policy_evidence",
        ],
    },
    RequiredSource {
        path: "crates/security/chio-flow/src/classification.rs",
        symbols: &[
            "CategoryLabelMap::bindings",
            "CategoryLabelMap::verify_result",
            "VerifiedClassification",
            "VerifiedClassification::evidence",
            "VerifiedClassification::fmt",
            "VerifiedClassification::tenant_id",
            "VerifiedClassification::label",
            "VerifiedClassification::classifier_id",
            "VerifiedClassification::classifier_version",
            "VerifiedClassification::finding_count",
            "VerifiedClassification::request_id",
            "VerifiedClassification::payload_digest",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/native_flow/policy.rs",
        symbols: &[
            "MAX_POLICY_BYTES",
            "NativeFlowPolicyEvidence",
            "NativeFlowPolicyEvidence::canonical_bytes",
            "NativeFlowPolicyEvidence::digest",
            "PreparedInputs",
            "PreparedInputs::capture",
            "PreparedInputs::finish",
            "bounded_value",
            "canonical_bounded",
        ],
    },
];

const NATIVE_DISPATCH_LEDGER_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/capture_ack.rs",
        symbols: &["verify"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/native_capture_readback.rs",
        symbols: &["SqliteAdmissionOperationStore::load_native_dispatch_capture"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/budget_store/composite/native_capture.rs",
        symbols: &["SqliteBudgetStore::load_native_capture_decision_tx","verify_capture_quota_delta","verify_capture_cumulative_delta"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/budget_store/composite/transitions.rs",
        symbols: &["transition_decision_from_event"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/lib.rs",
        symbols: &["SqliteAdmissionOperationStore::capture_native_invocation_and_commit_dispatch","SqliteAdmissionOperationStore::load_native_dispatch_capture"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/participant.rs",
        symbols: &["BudgetCaptureAdvance"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/capture.rs",
        symbols: &["NativeCaptureCheckpointInput"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/evaluation/native_capture_checkpoint.rs",
        symbols: &["NativeCaptureCheckpointContext", "NativeCaptureCheckpointOutcome", "ChioKernel::evaluate_native_capture_checkpoint"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/evaluation/evaluation_helpers.rs",
        symbols: &["ChioKernel::prepare_changed_ordinary_recovery_status"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/authority_profile.rs",
        symbols: &["DurableToolAdmission::original_native_security_authority_binding", "DurableToolAdmission::original_retained_request"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/credential_reservation/native_dispatch.rs",
        symbols: &["VerifiedNativeDispatchCredentials", "VerifiedNativeDispatchCredentials::validate_binding", "DispatchCredentialReservation::verify_native_dispatch", "VerifiedNativeDispatchCredentials::runtime_validity", ],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/capture.rs",
        symbols: &["NativeSecurityDispatchCaptureAuthority", "NativeSecurityDispatchCaptureAuthority::prepare_egress", "NativeSecurityDispatchCaptureAuthority::capture", "ChioKernel::reach_native_capture_checkpoint"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/capture.rs",
        symbols: &["NativeCaptureBinding", "VerifiedNativeCapture", "VerifiedNativeCapture::verify", "VerifiedNativeCapture::verify_owner", "VerifiedNativeCapture::verify_transition", "VerifiedNativeCapture::verify_deadline", "VerifiedNativeCapture::validate_time", "verify_capture_attachment"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/receipt_store.rs",
        symbols: &["AdmissionNativeDispatchCapture", "QualifiedAdmissionProjectionStore"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/authority_profile.rs",
        symbols: &["AdmissionAuthorityProfileV1::selection"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/retained_request.rs",
        symbols: &["RetainedToolAdmissionRequestV1::matching_grants_require_dpop"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/runtime_acquisition.rs",
        symbols: &["ChioKernel::verify_owned_runtime_for_native_capture"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/ledger.rs",
        symbols: &["PreparedNativeSecurityEgress::retain_for_capture"],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/native_flow.rs",
        symbols: &["PreparedNativeFlowDispatch::capture_invocation"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_dispatch.rs",
        symbols: &["verify_native_dispatch_capture_owner_tx"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/participant.rs",
        symbols: &["advance_budget_capture_tx"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store.rs",
        symbols: &["SqliteAdmissionOperationStore::capture_native_invocation_and_commit_dispatch"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/native_dispatch_ledger.rs",
        symbols: &["NativeSecurityDispatchLedgerContext", "NativeSecurityDispatchLedgerRecordV1", "NativeSecurityDispatchLedgerContext::fmt", "NativeSecurityDispatchLedgerRecordV1::fmt"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/ledger.rs",
        symbols: &["PreparedNativeSecurityEgress::acquire_and_commit_with_dispatch_ledger", "PreparedNativeSecurityEgress::validate_ledger_input", "PreparedNativeSecurityEgress::retain_dispatch_ledger", "PreparedNativeSecurityEgress::retain_dispatch_ledger_current", "PreparedNativeSecurityEgress::validate_ledger", "AcquiredNativeSecurityEgress::commit_with_dispatch_ledger"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress.rs",
        symbols: &["AcquiredNativeSecurityEgress::commit_current"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/admission_operation/store.rs",
        symbols: &["AdmissionOperationStore"],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/native_flow.rs",
        symbols: &["PreparedNativeFlowDispatch::commit_custody_with_dispatch_ledger", "PreparedNativeFlowDispatch::commit_custody_inner", "NativeFlowCustody::dispatch_ledger"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/store.rs",
        symbols: &["SqliteAdmissionOperationStore::retain_native_dispatch_ledger", "SqliteAdmissionOperationStore::load_native_dispatch_ledger"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger.rs",
        symbols: &["SCHEMA", "PROJECTION", "MUTATION", "MAX_RECORD_BYTES", "sql", "require_operation", "projection_reference", "SqliteAdmissionOperationStore::load_native_dispatch_ledger"],
    },
    RequiredSource {
        path: "crates/security/chio-security-types/src/flow.rs",
        symbols: &[
            "NATIVE_FLOW_DISPATCH_POLICY_SCHEMA",
            "NATIVE_FLOW_DECLASSIFIED_DISPATCH_POLICY_SCHEMA",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/policy.rs",
        symbols: &["MAX_POLICY_BYTES", "Policy", "Inputs", "Decision", "required_option", "decode", "Policy::validate_binding", "Policy::validate_current", "Policy::validate_at"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/record.rs",
        symbols: &["Record", "Record::bytes", "Record::digest", "Record::evidence", "Record::validate"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/storage.rs",
        symbols: &["current_operation", "load", "verify_coverage", "verify_reference", "verify_all"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/write.rs",
        symbols: &["SqliteAdmissionOperationStore::retain_native_dispatch_ledger"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/runtime_participant/dispatch_snapshot.rs",
        symbols: &["dispatch_snapshot", "verify_dispatch_snapshot"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/governed_approval_claim/dispatch_snapshot.rs",
        symbols: &["dispatch_snapshot", "verify_dispatch_snapshot"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/dpop_claim/dispatch_snapshot.rs",
        symbols: &["dispatch_snapshot", "verify_dispatch_snapshot"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/schema.rs",
        symbols: &["initialize_admission_operation_schema", "verify_admission_operation_invariants", "verify_admission_operation_schema", "admission_operation_schema_catalog"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/schema.rs",
        symbols: &["digest", "expected", "verify"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/schema_version/creation.rs",
        symbols: &[
            "METADATA_SCHEMA",
            "SchemaTransaction::from_transaction",
            "SchemaTransaction::stamp",
            "SchemaTransaction::commit",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain.rs",
        symbols: &[
            "GLOBAL_COMMIT_SCHEMA",
            "budget_event_reference_digest",
            "initialize_global_commit_schema",
            "verify_global_commit_schema",
            "global_schema_catalog",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/serving_owner/global_commit_chain/projection_reference.rs",
        symbols: &["projection_reference_digest"],
    },
];

const NATIVE_OUTPUT_PREPARATION_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_output.rs",
        symbols: &[
            "NativeSecurityOutputJoinAuthority",
            "NativeSecurityOutputJoinAuthority::join_output",
            "NativeSecurityOutputJoinAuthority::join_once",
            "NativeSecurityOutputJoinAuthority::validate_original",
            "NativeSecurityOutputJoinAuthority::read_history",
            "NativeSecurityOutputJoinAuthority::finish",
            "ChioKernel::prepare_durable_native_output",
        ],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/native_flow/output.rs",
        symbols: &[
            "NativeFlowResolver::classify_output",
            "NativeFlowResolver::classified_output_label",
        ],
    },
];

// Consumption and outcome remain closed commands under original affine owners.
const NATIVE_USE_SOURCES: &[RequiredSource] = &[
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/credential_reservation/native_dispatch.rs",
        symbols: &["VerifiedNativeDispatchCredentials::execution_nonce", "DispatchCredentialReservation::verify_native_execution_nonce"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress/ledger.rs",
        symbols: &["PreparedNativeSecurityEgress::retain_for_declassified_capture", "PreparedNativeSecurityEgress::retain_for_capture_inner"],
    },
    RequiredSource {
        path: "crates/kernel/chio-kernel/src/kernel/admission_coordinator/native_egress.rs",
        symbols: &["AcquiredNativeSecurityEgress::commit_current_with_declassification"],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/native_flow.rs",
        symbols: &["NativeFlowResolver::validate_declassification_issuer"],
    },
    RequiredSource {
        path: "crates/platform/chio-control-plane/src/security/adapters/native_flow/declassification.rs",
        symbols: &["prepare_consumption", "confirm_consumption"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/security_state/native_egress.rs",
        symbols: &["NativeEgressCommand", "NativeEgressCommand::declassified", "NativeEgressCommand::permits_table", "NativeEgressCommand::expected_changes", "NativeEgressCommand::validate_changes"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/security_state/native_declassification.rs",
        symbols: &["TABLES", "consumption_changes", "NativeDeclassificationOutcome", "NativeDeclassificationOutcome::released", "NativeDeclassificationOutcome::changes", "NativeDeclassificationOutcome::validate_change", "NativeDeclassificationOutcome::validate_changes"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/security_state/declassification.rs",
        symbols: &["verify_native_pending_declassification"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/security_state/native_mutation.rs",
        symbols: &["CapturePlan", "CapturePlan::max_changes"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/egress/write.rs",
        symbols: &["SqliteAdmissionOperationStore::commit_declassified_egress_from_port"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/egress/contract.rs",
        symbols: &["validate_declassification_binding"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/egress/record.rs",
        symbols: &["Record::format"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/dispatch_ledger/policy.rs",
        symbols: &["Policy::validate_live_declassification", "Policy::validate_owned_declassification"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/output/declassification.rs",
        symbols: &["expected"],
    },
    RequiredSource {
        path: "crates/platform/chio-store-sqlite/src/admission_operation_store/security_participant_state/output/record.rs",
        symbols: &["Record::format"],
    },
];

const REQUIRED_COVERAGE: &[(&str, &[RequiredSource])] = &[
    (
        "formal/apalache/KernelTransitionCancelSafe.tla",
        CANCELLATION_BOUNDARY_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        EXTRACTED_IMPLEMENTATION_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        DROP_CONSTRUCTION_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        NATIVE_USE_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        NATIVE_LIFECYCLE_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        NATIVE_OUTPUT_PREPARATION_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        NATIVE_DISPATCH_LEDGER_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        NATIVE_POLICY_EVIDENCE_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        NATIVE_INPUT_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        NATIVE_NONCE_PREFLIGHT_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        NATIVE_CAPTURE_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        RUNTIME_OWNERSHIP_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        RUNTIME_PREPARATION_SOURCES,
    ),
    ("formal/tla/RevocationPropagation.tla", REQUIRED_SOURCES),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        REQUIRED_SOURCES,
    ),
    ("formal/tla/RevocationPropagation.tla", REVOCATION_SOURCES),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        CALLER_SHARE_SOURCES,
    ),
    (
        "formal/apalache/PostAdmissionDropGuard.tla",
        DISPATCH_COMMIT_SOURCES,
    ),
];

pub(super) fn validate(entries: &[MirrorEntry]) -> Result<(), String> {
    for (model, sources) in REQUIRED_COVERAGE {
        for source in *sources {
            let entry = entries.iter().find(|entry| {
                entry.model_file == *model
                    && entry.model_kind == ModelKind::Tla
                    && entry.relationship == MirrorRelationship::AbstractionAnchor
                    && entry.rust_source == source.path
            });
            for symbol in source.symbols {
                if !entry.is_some_and(|entry| entry.rust_symbols.iter().any(|name| name == symbol))
                {
                    return Err(format!(
                        "required dispatch abstraction anchor missing: {model} -> {}::{symbol}; \
                         forwarding wrappers alone do not cover the reviewed implementation",
                        source.path,
                    ));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;

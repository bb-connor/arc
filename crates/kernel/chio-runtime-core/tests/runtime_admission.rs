use chio_kernel::{RuntimeAdmissionHook, RuntimeAdmissionRevalidationContext};
use chio_runtime_core as runtime_api;
use chio_runtime_core::CHIO_RUNTIME_FAILURE_CODES;
include!("support/runtime_admission.rs");

#[path = "runtime_admission/operation_owned.rs"]
#[cfg(unix)]
mod operation_owned;
#[path = "runtime_admission/swarm_binding.rs"]
mod swarm_binding;
#[path = "runtime_admission/swarm_evolution.rs"]
mod swarm_evolution;

#[test]
fn runtime_failure_code_registry_covers_hook_surface_codes() {
    let registry: std::collections::BTreeSet<_> =
        CHIO_RUNTIME_FAILURE_CODES.iter().copied().collect();
    assert_eq!(registry.len(), CHIO_RUNTIME_FAILURE_CODES.len());

    for code in [
        "admission_bundle_id_mismatch",
        "runtime_trust_floor_store_unsupported",
        "runtime_source_qualification_invalid",
        "runtime_store_schema_mismatch",
        "missing_governed_intent",
        "missing_chio_admission_context",
        "invalid_chio_admission_context",
        "missing_admission_id",
        "invalid_chio_swarm_context",
        "missing_chio_swarm_context",
        "runtime_admission_swarm_unsupported",
        "invalid_chio_swarm_evidence_ref",
        "missing_chio_swarm_evidence_ref",
        "missing_chio_swarm_authority_bundle",
        "chio_swarm_authority_ref_mismatch",
        "chio_swarm_authority_rejected",
        "chio_swarm_continuation_replay",
        "chio_swarm_continuation_store_unsupported",
        "missing_chio_treaty_context",
        "invalid_chio_treaty_context",
        "request_smuggled_trust_root",
        "request_smuggled_dynamic_trust",
        "missing_treaty_scope_id",
        "missing_treaty_scope_hash",
        "missing_ladder_intersection_id",
        "missing_ladder_intersection_hash",
        "missing_action_class_id",
        "invalid_chio_treaty_hash",
        "invalid_chio_treaty_evidence_ref",
        "missing_chio_treaty_evidence_ref",
        "chio_treaty_missing_scope",
        "chio_treaty_scope_hash_mismatch",
        "chio_treaty_missing_intersection",
        "unsupported_cross_kernel_continuation_schema",
        "continuation_invalid_window",
        "unsupported_receipt_lineage_statement_schema",
        "receipt_lineage_invalid_evidence_class",
        "chio_ladder_invalid_consistency_model",
        "chio_ladder_invalid_cosign_mode",
        "unsupported_runtime_step_evidence_schema",
        "runtime_step_evidence_missing_admission_id",
        "runtime_step_evidence_missing_consistency_anchor",
        "runtime_step_evidence_missing_governance",
        "duplicate_consumed_swarm_continuation",
    ] {
        assert!(
            registry.contains(code),
            "runtime failure code registry missing {code}"
        );
    }
}

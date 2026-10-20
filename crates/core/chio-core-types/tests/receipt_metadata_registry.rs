//! Contract tests for the receipt-metadata key registry and the guard
//! evidence declaration.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use chio_core_types::receipt::metadata::{
    check_internal_receipt_metadata, metadata_key_spec, EvidenceDisclosure,
    GuardEvidenceDeclaration, MetadataDisclosure, MetadataKeyOrigin, RECEIPT_METADATA_KEYS,
};
use serde_json::json;

/// How each top-level metadata key found by the receipt-metadata census is
/// treated by the registry.
enum CensusOutcome {
    /// Registered with this origin and disclosure.
    Registered(MetadataKeyOrigin, MetadataDisclosure),
    /// Carries raw identifiers or a whole content preimage; deliberately
    /// unregistered so a committed receipt refuses it until a projection
    /// replaces it.
    AwaitingProjection,
}

use CensusOutcome::{AwaitingProjection, Registered};
use MetadataDisclosure::{CommittedSafe, Unsafe};
use MetadataKeyOrigin::{CallerOrHook, ChioInternal};

const CENSUS: &[(&str, CensusOutcome)] = &[
    (
        "admission_operation",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("attribution", Registered(ChioInternal, CommittedSafe)),
    (
        "chio_manifest_security_v1",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("protocol_admission", Registered(ChioInternal, Unsafe)),
    ("budget_authority", Registered(ChioInternal, CommittedSafe)),
    (
        "budget_denial_authority",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("financial", Registered(ChioInternal, Unsafe)),
    ("governed_transaction", Registered(ChioInternal, Unsafe)),
    (
        "governed_transaction_diagnostics",
        Registered(ChioInternal, Unsafe),
    ),
    ("model_metadata", Registered(ChioInternal, CommittedSafe)),
    ("channel", Registered(ChioInternal, CommittedSafe)),
    ("caller_delivery", Registered(ChioInternal, CommittedSafe)),
    ("protocol_refusal", Registered(ChioInternal, CommittedSafe)),
    ("chio_runtime", Registered(ChioInternal, CommittedSafe)),
    ("receipt_context", Registered(ChioInternal, Unsafe)),
    ("delivery_contract", Registered(ChioInternal, Unsafe)),
    ("finding_delivery", Registered(ChioInternal, CommittedSafe)),
    ("finding_recovery", Registered(ChioInternal, CommittedSafe)),
    (
        "finding_purchase_replay_snapshot",
        Registered(ChioInternal, CommittedSafe),
    ),
    (
        "finding_recovery_replay_snapshot",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("findingDenial", Registered(ChioInternal, CommittedSafe)),
    (
        "chio_receipt_signing_nonce",
        Registered(ChioInternal, Unsafe),
    ),
    ("original_metadata", Registered(CallerOrHook, Unsafe)),
    ("prior_metadata", Registered(CallerOrHook, Unsafe)),
    ("stream", Registered(ChioInternal, Unsafe)),
    (
        "threshold_approval",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("memory_provenance", Registered(ChioInternal, Unsafe)),
    ("post_invocation", Registered(ChioInternal, Unsafe)),
    ("execution_nonce", Registered(ChioInternal, CommittedSafe)),
    ("chio_kernel", Registered(ChioInternal, CommittedSafe)),
    ("runtime_admission", Registered(ChioInternal, CommittedSafe)),
    (
        "active_response_terminal_evidence",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("finding_pool_mutation", Registered(ChioInternal, Unsafe)),
    ("session_report", Registered(ChioInternal, Unsafe)),
    ("native_launch", Registered(ChioInternal, CommittedSafe)),
    ("provenance", Registered(CallerOrHook, Unsafe)),
    ("chio_process", Registered(CallerOrHook, Unsafe)),
    ("route", Registered(CallerOrHook, CommittedSafe)),
    ("route_selection", Registered(CallerOrHook, Unsafe)),
    ("source_receipt_context", Registered(CallerOrHook, Unsafe)),
    ("lineageReferences", Registered(CallerOrHook, CommittedSafe)),
    ("workflow_id", Registered(CallerOrHook, CommittedSafe)),
    ("vendor_id", Registered(CallerOrHook, CommittedSafe)),
    ("chio_http_receipt_v1", Registered(ChioInternal, Unsafe)),
    (
        "chio_http_status_scope",
        Registered(ChioInternal, CommittedSafe),
    ),
    (
        "chio_decision_receipt_id",
        Registered(ChioInternal, CommittedSafe),
    ),
    (
        "chio_kernel_receipt_id",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("otel", Registered(ChioInternal, Unsafe)),
    ("correlation", Registered(ChioInternal, CommittedSafe)),
    (
        "keyEnterpriseReceipt",
        Registered(ChioInternal, CommittedSafe),
    ),
    (
        "active_defense_evidence_id",
        Registered(ChioInternal, Unsafe),
    ),
    (
        "occurred_at_unix_ms",
        Registered(ChioInternal, CommittedSafe),
    ),
    (
        "response_simulation_evidence_id",
        Registered(ChioInternal, Unsafe),
    ),
    (
        "active_defense_backfill_v1",
        Registered(ChioInternal, Unsafe),
    ),
    ("scimLifecycle", Registered(ChioInternal, Unsafe)),
    ("mercury", Registered(ChioInternal, Unsafe)),
    ("authorizationContext", Registered(ChioInternal, Unsafe)),
    ("guardOutcome", Registered(ChioInternal, Unsafe)),
    ("deniedAccessRecord", Registered(ChioInternal, Unsafe)),
    ("policySnapshot", Registered(ChioInternal, CommittedSafe)),
    ("acp", Registered(ChioInternal, Unsafe)),
    (
        "agent_web_receipt_ref",
        Registered(ChioInternal, CommittedSafe),
    ),
    (
        "parent_receipt_ids",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("batch_witness", Registered(ChioInternal, Unsafe)),
    ("active_defense_body", AwaitingProjection),
    ("response_simulation_report", AwaitingProjection),
    ("security_event_projection", AwaitingProjection),
    ("cage_receipt", AwaitingProjection),
    ("schema", AwaitingProjection),
];

#[test]
fn registry_covers_census_keys() {
    for (key, outcome) in CENSUS {
        let spec = metadata_key_spec(key);
        match outcome {
            Registered(origin, disclosure) => {
                let spec = spec.unwrap_or_else(|| panic!("census key {key} is unregistered"));
                assert_eq!(spec.origin, *origin, "origin of {key}");
                assert_eq!(spec.disclosure, *disclosure, "disclosure of {key}");
            }
            AwaitingProjection => {
                assert!(spec.is_none(), "{key} must stay unregistered");
            }
        }
    }
    let census: BTreeSet<&str> = CENSUS.iter().map(|(key, _)| *key).collect();
    for spec in RECEIPT_METADATA_KEYS {
        assert!(
            census.contains(spec.key),
            "registered key {} is missing from the census",
            spec.key
        );
    }
}

#[test]
fn registry_keys_are_unique_and_audited() {
    let mut seen = BTreeSet::new();
    for spec in RECEIPT_METADATA_KEYS {
        assert!(seen.insert(spec.key), "duplicate registry key {}", spec.key);
        assert!(!spec.reason.trim().is_empty(), "{} has no audit", spec.key);
        assert_eq!(metadata_key_spec(spec.key), Some(spec));
    }
}

#[test]
fn unknown_metadata_key_is_refused() {
    assert!(metadata_key_spec("unregistered_block").is_none());
    let error = check_internal_receipt_metadata(&json!({ "unregistered_block": {} }))
        .expect_err("an unregistered key must refuse");
    assert!(error.to_string().contains("unregistered_block"), "{error}");
}

#[test]
fn unsafe_and_caller_keys_are_refused_in_internal_metadata() {
    for spec in RECEIPT_METADATA_KEYS {
        let result = check_internal_receipt_metadata(&json!({ spec.key: {} }));
        let admissible =
            spec.origin == ChioInternal && spec.disclosure == MetadataDisclosure::CommittedSafe;
        assert_eq!(result.is_ok(), admissible, "{}", spec.key);
    }
}

#[test]
fn internal_metadata_must_be_an_object() {
    for value in [json!(null), json!([]), json!("financial"), json!(1)] {
        assert!(check_internal_receipt_metadata(&value).is_err(), "{value}");
    }
    assert!(check_internal_receipt_metadata(&json!({})).is_ok());
}

#[test]
fn guard_evidence_declarations_never_pair_unsafe_with_required() {
    let declarations = [
        GuardEvidenceDeclaration::SAFE,
        GuardEvidenceDeclaration::SAFE_REQUIRED,
        GuardEvidenceDeclaration::UNSAFE,
    ];
    for declaration in declarations {
        assert!(
            !(declaration.details() == EvidenceDisclosure::Unsafe
                && declaration.details_required()),
            "{declaration:?}"
        );
    }
    assert_eq!(
        GuardEvidenceDeclaration::UNSAFE.details(),
        EvidenceDisclosure::Unsafe
    );
    assert!(GuardEvidenceDeclaration::SAFE_REQUIRED.details_required());
    assert!(!GuardEvidenceDeclaration::SAFE.details_required());
}

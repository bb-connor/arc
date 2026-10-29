//! Contract tests for the receipt-metadata key registry and the guard
//! evidence declaration.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::BTreeSet;

use chio_core_types::receipt::metadata::{
    check_internal_receipt_metadata, metadata_key_spec, reserved_receipt_metadata_keys,
    EvidenceDisclosure, GuardEvidenceDeclaration, MetadataDisclosure, MetadataForm,
    MetadataKeyOrigin, MetadataKeySpec, RECEIPT_METADATA_KEYS,
};
use serde_json::json;

const PROTOCOL: &str = include_str!("../../../../spec/PROTOCOL.md");

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
use MetadataForm::{Commitments, Plaintext, Projection, Removed};
use MetadataKeyOrigin::{CallerOrHook, ChioInternal};

const CENSUS: &[(&str, CensusOutcome)] = &[
    ("admission_operation", Registered(ChioInternal, Unsafe)),
    ("attribution", Registered(ChioInternal, Unsafe)),
    (
        "chio_manifest_security_v1",
        Registered(ChioInternal, Unsafe),
    ),
    ("protocol_admission", Registered(ChioInternal, Unsafe)),
    ("budget_authority", Registered(ChioInternal, CommittedSafe)),
    ("budget_denial_authority", Registered(ChioInternal, Unsafe)),
    ("financial", Registered(ChioInternal, Unsafe)),
    ("governed_transaction", Registered(ChioInternal, Unsafe)),
    ("caller_delivery", Registered(ChioInternal, CommittedSafe)),
    ("protocol_refusal", Registered(ChioInternal, Unsafe)),
    ("chio_runtime", Registered(ChioInternal, CommittedSafe)),
    ("session_anchor", Registered(ChioInternal, CommittedSafe)),
    ("receipt_context", Registered(ChioInternal, Unsafe)),
    (
        "governed_transaction_diagnostics",
        Registered(ChioInternal, Unsafe),
    ),
    ("model_metadata", Registered(ChioInternal, Unsafe)),
    ("channel", Registered(ChioInternal, Unsafe)),
    ("delivery_contract", Registered(ChioInternal, Unsafe)),
    ("finding_delivery", Registered(ChioInternal, CommittedSafe)),
    ("finding_recovery", Registered(ChioInternal, CommittedSafe)),
    (
        "finding_purchase_replay_snapshot",
        Registered(ChioInternal, CommittedSafe),
    ),
    (
        "decision_model_witness",
        Registered(ChioInternal, CommittedSafe),
    ),
    (
        "finding_recovery_replay_snapshot",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("findingDenial", Registered(ChioInternal, Unsafe)),
    ("stream", Registered(ChioInternal, Unsafe)),
    (
        "threshold_approval",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("memory_provenance", Registered(ChioInternal, Unsafe)),
    ("post_invocation", Registered(ChioInternal, Unsafe)),
    ("execution_nonce", Registered(ChioInternal, CommittedSafe)),
    ("chio_kernel", Registered(ChioInternal, Unsafe)),
    ("runtime_admission", Registered(ChioInternal, Unsafe)),
    (
        "active_response_terminal_evidence",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("chio_http_receipt_v1", Registered(ChioInternal, Unsafe)),
    (
        "chio_receipt_signing_nonce",
        Registered(ChioInternal, Unsafe),
    ),
    ("original_metadata", Registered(ChioInternal, Unsafe)),
    ("finding_pool_mutation", Registered(ChioInternal, Unsafe)),
    ("session_report", Registered(ChioInternal, Unsafe)),
    ("prior_metadata", Registered(ChioInternal, Unsafe)),
    ("lineageReferences", Registered(ChioInternal, Unsafe)),
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
    ("correlation", Registered(ChioInternal, Unsafe)),
    ("keyEnterpriseReceipt", Registered(ChioInternal, Unsafe)),
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
    ("scimLifecycle", Registered(ChioInternal, Unsafe)),
    ("mercury", Registered(ChioInternal, Unsafe)),
    ("authorizationContext", Registered(ChioInternal, Unsafe)),
    ("guardOutcome", Registered(ChioInternal, Unsafe)),
    ("deniedAccessRecord", Registered(ChioInternal, Unsafe)),
    ("policySnapshot", Registered(ChioInternal, Unsafe)),
    ("acp", Registered(ChioInternal, Unsafe)),
    ("agent_web_receipt_ref", Registered(ChioInternal, Unsafe)),
    ("parent_receipt_ids", Registered(ChioInternal, Unsafe)),
    ("batch_witness", Registered(ChioInternal, Unsafe)),
    ("active_defense", Registered(ChioInternal, CommittedSafe)),
    (
        "response_simulation",
        Registered(ChioInternal, CommittedSafe),
    ),
    ("security_event", Registered(ChioInternal, CommittedSafe)),
    ("cage_receipt", Registered(ChioInternal, Unsafe)),
    ("guard_error", Registered(ChioInternal, CommittedSafe)),
    ("refusal", Registered(ChioInternal, CommittedSafe)),
    ("cancellation", Registered(ChioInternal, CommittedSafe)),
    ("native_launch", Registered(CallerOrHook, Unsafe)),
    ("provenance", Registered(CallerOrHook, Unsafe)),
    ("chio_process", Registered(CallerOrHook, Unsafe)),
    ("route", Registered(CallerOrHook, Unsafe)),
    ("route_selection", Registered(CallerOrHook, Unsafe)),
    ("source_receipt_context", Registered(CallerOrHook, Unsafe)),
    ("workflow_id", Registered(CallerOrHook, Unsafe)),
    ("vendor_id", Registered(CallerOrHook, Unsafe)),
    ("active_defense_body", AwaitingProjection),
    ("response_simulation_report", AwaitingProjection),
    ("security_event_projection", AwaitingProjection),
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

/// The reserved set is derived, never listed: it is exactly the
/// `ChioInternal` keys in registry order.
#[test]
fn reserved_keys_are_exactly_the_chio_internal_keys() {
    let reserved: Vec<&str> = reserved_receipt_metadata_keys().collect();
    let chio_internal: Vec<&str> = RECEIPT_METADATA_KEYS
        .iter()
        .filter(|spec| spec.origin == ChioInternal)
        .map(|spec| spec.key)
        .collect();
    assert_eq!(reserved, chio_internal);
    for spec in RECEIPT_METADATA_KEYS {
        assert_eq!(
            reserved.contains(&spec.key),
            spec.origin == ChioInternal,
            "{}",
            spec.key
        );
    }
}

/// Keys written only on the signing path or by the HTTP receipt projection
/// are Chio-internal, so caller metadata naming them is refused.
#[test]
fn signing_path_and_projection_keys_are_reserved() {
    for key in [
        "chio_http_receipt_v1",
        "chio_receipt_signing_nonce",
        "original_metadata",
        "prior_metadata",
    ] {
        let spec = metadata_key_spec(key).unwrap();
        assert_eq!(spec.origin, ChioInternal, "{key}");
        assert!(reserved_receipt_metadata_keys().any(|reserved| reserved == key));
    }
}

/// A caller or hook value is committed by default, so no caller-origin key
/// reads as committed-safe, and receipt assembly drops every one.
#[test]
fn caller_origin_keys_are_unsafe() {
    for spec in RECEIPT_METADATA_KEYS {
        if spec.origin == CallerOrHook {
            assert_eq!(spec.disclosure, Unsafe, "{}", spec.key);
            assert_eq!(spec.form, Removed, "{}", spec.key);
        }
    }
}

/// Keys whose production writer emits the registered form today. A key joins
/// this list in the commit that changes its writer to the registered form.
const WRITER_EMITS_REGISTERED_FORM: &[&str] = &[
    "budget_authority",
    "caller_delivery",
    "chio_runtime",
    "session_anchor",
    "finding_delivery",
    "finding_recovery",
    "finding_purchase_replay_snapshot",
    "finding_recovery_replay_snapshot",
    "decision_model_witness",
    "threshold_approval",
    "execution_nonce",
    "active_response_terminal_evidence",
    "chio_http_status_scope",
    "chio_decision_receipt_id",
    "chio_kernel_receipt_id",
    "occurred_at_unix_ms",
    "active_defense",
    "response_simulation",
    "security_event",
    "guard_error",
    "refusal",
    "cancellation",
];

/// `disclosure` never claims more than the current writer emits: a
/// committed-safe key has a retained form and a writer that already emits it,
/// and a key whose target form is removal stays unsafe.
#[test]
fn committed_safe_disclosure_never_outruns_the_writer() {
    for spec in RECEIPT_METADATA_KEYS {
        if spec.disclosure == CommittedSafe {
            assert_ne!(spec.form, Removed, "{}", spec.key);
            assert!(
                WRITER_EMITS_REGISTERED_FORM.contains(&spec.key),
                "{} is committed-safe but its writer does not emit the registered form",
                spec.key
            );
        }
    }
    for key in WRITER_EMITS_REGISTERED_FORM {
        assert!(metadata_key_spec(key).is_some(), "{key} is unregistered");
    }
}

/// The projection and detail keys are signer-written, so caller metadata
/// naming one is refused, and each carries its registered form.
#[test]
fn projection_and_detail_keys_are_registered_in_their_forms() {
    for (key, disclosure, form) in [
        ("active_defense", CommittedSafe, Projection),
        ("response_simulation", CommittedSafe, Projection),
        ("security_event", CommittedSafe, Projection),
        ("cage_receipt", Unsafe, Projection),
        ("guard_error", CommittedSafe, Commitments),
        ("refusal", CommittedSafe, Commitments),
        ("cancellation", CommittedSafe, Commitments),
    ] {
        let spec = metadata_key_spec(key).unwrap_or_else(|| panic!("{key} is unregistered"));
        assert_eq!(
            (spec.origin, spec.disclosure, spec.form),
            (ChioInternal, disclosure, form),
            "{key}"
        );
        assert!(reserved_receipt_metadata_keys().any(|reserved| reserved == key));
    }
    assert_eq!(
        metadata_key_spec("cage_receipt").and_then(|spec| spec.schema),
        Some("chio.cage.receipt-metadata.v1")
    );
}

/// The cage producer still writes the raw cage receipt body under
/// `cage_receipt`, so the key refuses until the producer writes the projection.
#[test]
fn raw_cage_receipt_block_refuses_until_projected() {
    let error = check_internal_receipt_metadata(&json!({ "cage_receipt": {} }))
        .expect_err("the raw cage block must refuse");
    assert_eq!(
        error.to_string(),
        "canonical JSON error: receipt metadata key \"cage_receipt\" is not committed-safe"
    );
}

/// Every form appears in the registry.
#[test]
fn every_form_is_used() {
    for form in [Plaintext, Projection, Commitments, Removed] {
        assert!(
            RECEIPT_METADATA_KEYS.iter().any(|spec| spec.form == form),
            "{form:?}"
        );
    }
}

/// `protocol_refusal` carries unsalted digests of the wire request, its method
/// and target, and `admission_operation` an unsalted request binding hash over
/// the arguments, so both are unsafe until their digests become salted
/// commitments.
#[test]
fn request_digest_blocks_are_unsafe_until_committed() {
    for key in ["protocol_refusal", "admission_operation"] {
        let spec = metadata_key_spec(key).unwrap();
        assert_eq!(
            (spec.origin, spec.disclosure),
            (ChioInternal, Unsafe),
            "{key}"
        );
        let error = check_internal_receipt_metadata(&json!({ key: {} }))
            .expect_err("an unsafe key must refuse");
        assert_eq!(
            error.to_string(),
            format!("canonical JSON error: receipt metadata key {key:?} is not committed-safe"),
        );
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
fn active_defense_backfill_key_is_unregistered() {
    assert!(metadata_key_spec("active_defense_backfill_v1").is_none());
    let error = check_internal_receipt_metadata(&json!({ "active_defense_backfill_v1": {} }))
        .expect_err("the retired backfill key must refuse");
    assert_eq!(
        error.to_string(),
        "canonical JSON error: receipt metadata key \"active_defense_backfill_v1\" is not registered"
    );
}

#[test]
fn unsafe_and_caller_keys_are_refused_in_internal_metadata() {
    for spec in RECEIPT_METADATA_KEYS {
        let result = check_internal_receipt_metadata(&json!({ spec.key: {} }));
        let admissible = spec.origin == ChioInternal && spec.disclosure == CommittedSafe;
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

fn render_row(spec: &MetadataKeySpec) -> String {
    let origin = match spec.origin {
        ChioInternal => "Chio signer",
        CallerOrHook => "caller or hook",
    };
    let disclosure = match spec.disclosure {
        CommittedSafe => "committed-safe",
        Unsafe => "unsafe",
    };
    let form = match spec.form {
        Plaintext => "plaintext",
        Projection => "projection",
        Commitments => "commitments",
        Removed => "removed",
    };
    let schema = spec
        .schema
        .map(|schema| format!("`{schema}`"))
        .unwrap_or_default();
    format!(
        "| `{}` | {origin} | {disclosure} | {form} | {schema} | {} |",
        spec.key, spec.reason
    )
}

/// The key table in `spec/PROTOCOL.md` 6.4 is the registry, row for row.
#[test]
fn protocol_key_table_renders_the_registry() {
    let mut expected = vec![
        "| Key | Origin | Disclosure | Form | Schema | Contents and audit |".to_string(),
        "|-----|--------|------------|------|--------|--------------------|".to_string(),
    ];
    expected.extend(RECEIPT_METADATA_KEYS.iter().map(render_row));

    let section = PROTOCOL
        .split_once("### 6.4 Receipt Metadata\n")
        .map(|(_, rest)| rest)
        .expect("PROTOCOL.md has section 6.4");
    let section = section.split("\n### ").next().unwrap_or(section);
    let table: Vec<String> = section
        .lines()
        .skip_while(|line| !line.starts_with("| Key | Origin |"))
        .take_while(|line| line.starts_with('|'))
        .map(str::to_string)
        .collect();
    assert!(
        table == expected,
        "spec/PROTOCOL.md 6.4 key table differs from the registry; expected:\n{}",
        expected.join("\n")
    );
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

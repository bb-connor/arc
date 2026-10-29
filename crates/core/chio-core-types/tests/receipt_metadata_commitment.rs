//! Metadata field commitments: domain, opening, strict wire form and the salt_ref inventory.

use chio_core_types::hashing::Sha256State;
use chio_core_types::receipt::commitment::{
    commit, CommitmentDomain, Salt, METADATA_COMMITMENT_DOMAIN, SALT_LEN,
};
use chio_core_types::receipt::metadata::{
    check_metadata_salt_ref, metadata_salt_ref, MetadataCommitment, MetadataCommitmentError,
    MetadataOpening, MetadataOpenings, MetadataValue,
};
use chio_core_types::rng::{Rng, RngError};
use chio_core_types::root_authority::{SaltRef, Sha256Digest};
use chio_test_support::prelude::*;
use serde_json::{json, Value};

fn salt_ref(text: &str) -> SaltRef {
    SaltRef::new(text).test_unwrap()
}

fn opening(fill: u8, value: &Value) -> MetadataOpening {
    MetadataOpening {
        salt: Salt::from_bytes([fill; SALT_LEN]),
        value: MetadataValue::from_json(value).test_unwrap(),
    }
}

struct FailingRng;

impl Rng for FailingRng {
    fn fill_bytes(&self, _dest: &mut [u8]) -> Result<(), RngError> {
        Err(RngError("offline"))
    }
}

struct FixedRng(u8);

impl Rng for FixedRng {
    fn fill_bytes(&self, dest: &mut [u8]) -> Result<(), RngError> {
        dest.fill(self.0);
        Ok(())
    }
}

#[test]
fn metadata_commitment_matches_layout() {
    let field = salt_ref("metadata.governed_transaction.purpose");
    let opening = opening(0x21, &json!({"b": 2, "a": "x"}));
    assert_eq!(opening.value.as_bytes(), br#"{"a":"x","b":2}"#);
    let mut state = Sha256State::new();
    state.update(b"chio.receipt.metadata.v1\0");
    state.update(b"metadata.governed_transaction.purpose");
    state.update(&[0]);
    state.update(&[0x21; SALT_LEN]);
    state.update(br#"{"a":"x","b":2}"#);
    let expected = Sha256Digest::from_hash(state.finalize());
    assert_eq!(METADATA_COMMITMENT_DOMAIN, b"chio.receipt.metadata.v1\0");
    let commitment = MetadataCommitment::compute(field.clone(), &opening).test_unwrap();
    assert_eq!(commitment.value(), &expected);
    assert_eq!(commitment.salt_ref(), &field);
    assert!(commitment.opens_to(&opening));
}

#[test]
fn metadata_domain_separates_from_every_other_commitment() {
    let salt = Salt::from_bytes([0x33; SALT_LEN]);
    let field = salt_ref("metadata.refusal.detail");
    let other_field = salt_ref("metadata.guard_error.detail");
    let metadata = commit(CommitmentDomain::Metadata(&field), &salt, b"\"x\"");
    for other in [
        CommitmentDomain::Parameters,
        CommitmentDomain::Content,
        CommitmentDomain::DelegationSubject,
        CommitmentDomain::DelegationTenant,
        CommitmentDomain::Metadata(&other_field),
    ] {
        assert_ne!(commit(other, &salt, b"\"x\""), metadata, "{other:?}");
    }
}

#[test]
fn metadata_opening_refuses_another_value_salt_or_field() {
    let field = salt_ref("metadata.security_event.subject");
    let held = opening(0x44, &json!("subject-a"));
    let commitment = MetadataCommitment::compute(field.clone(), &held).test_unwrap();
    assert!(!commitment.opens_to(&opening(0x44, &json!("subject-b"))));
    assert!(!commitment.opens_to(&opening(0x45, &json!("subject-a"))));
    let moved =
        MetadataCommitment::compute(salt_ref("metadata.security_event.other"), &held).test_unwrap();
    assert_ne!(moved.value(), commitment.value());

    let mut openings = MetadataOpenings::new();
    assert_eq!(
        openings.open(&commitment).test_unwrap_err(),
        MetadataCommitmentError::OpeningUnavailable {
            salt_ref: field.clone()
        }
    );
    openings
        .insert(field.clone(), opening(0x46, &json!("subject-a")))
        .test_unwrap();
    assert_eq!(
        openings.open(&commitment).test_unwrap_err(),
        MetadataCommitmentError::MetadataCommitmentMismatch { salt_ref: field }
    );
}

#[test]
fn metadata_openings_commit_draws_one_salt_per_field() {
    let mut openings = MetadataOpenings::new();
    let field = salt_ref("metadata.active_defense.action");
    assert_eq!(
        openings
            .commit(field.clone(), &json!("plan-1"), &FailingRng)
            .test_unwrap_err(),
        MetadataCommitmentError::Entropy(RngError("offline"))
    );
    assert!(openings.is_empty());

    let commitment = openings
        .commit(field.clone(), &json!("plan-1"), &FixedRng(1))
        .test_unwrap();
    assert_eq!(
        openings.open(&commitment).test_unwrap().value.as_bytes(),
        b"\"plan-1\""
    );
    assert_eq!(
        openings
            .commit(field.clone(), &json!("plan-2"), &FixedRng(2))
            .test_unwrap_err(),
        MetadataCommitmentError::DuplicateSaltRef { salt_ref: field }
    );
    let finding = salt_ref("metadata.active_defense.finding");
    assert_eq!(
        openings
            .commit(finding.clone(), &json!("finding-1"), &FixedRng(1))
            .test_unwrap_err(),
        MetadataCommitmentError::DuplicateSalt { salt_ref: finding }
    );
    assert_eq!(openings.len(), 1);
}

#[test]
fn metadata_openings_never_print_salt_or_value() {
    let held = opening(0x5a, &json!("marker-7c1f"));
    let mut openings = MetadataOpenings::new();
    openings
        .insert(salt_ref("metadata.refusal.detail"), held.clone())
        .test_unwrap();
    for printed in [
        format!("{held:?}"),
        format!("{:?}", held.value),
        format!("{openings:?}"),
    ] {
        assert!(!printed.contains("marker-7c1f"), "{printed}");
        assert!(!printed.contains("90"), "{printed}");
    }
}

#[test]
fn metadata_commitment_wire_form_is_strict() {
    let commitment = MetadataCommitment::compute(
        salt_ref("metadata.refusal.detail"),
        &opening(1, &json!("x")),
    )
    .test_unwrap();
    let encoded = serde_json::to_value(&commitment).test_unwrap();
    assert_eq!(encoded["alg"], json!("sha256-salted"));
    assert_eq!(encoded["salt_ref"], json!("metadata.refusal.detail"));
    assert_eq!(
        serde_json::from_value::<MetadataCommitment>(encoded.clone()).test_unwrap(),
        commitment
    );

    let mut padded = encoded.clone();
    padded["extra"] = Value::Null;
    assert_eq!(
        serde_json::from_value::<MetadataCommitment>(padded)
            .test_unwrap_err()
            .to_string(),
        "unknown field `extra`, expected one of `alg`, `value`, `salt_ref`"
    );
    let mut params = encoded;
    params["salt_ref"] = json!("params");
    assert_eq!(
        serde_json::from_value::<MetadataCommitment>(params)
            .test_unwrap_err()
            .to_string(),
        "`params` is not a metadata salt_ref"
    );
}

/// The cases of the `receipt_metadata_values.salt_ref` CHECK (plan census
/// `metadata-blocks/values-ddl.sql`): `metadata.[a-z]*`, `[a-z0-9_.]`, no `..`, no
/// trailing `.`, 10 to 64 bytes.
#[test]
fn metadata_salt_ref_check_matches_the_values_column() {
    for accepted in [
        "metadata.a",
        "metadata.a1.b_2",
        &format!("metadata.{}", "a".repeat(55)),
    ] {
        assert!(
            check_metadata_salt_ref(&salt_ref(accepted)).is_ok(),
            "{accepted}"
        );
    }
    for refused in [
        "metadata",
        "metadatax.a",
        "params",
        "content",
        "metadata.1a",
        "metadata._a",
    ] {
        let Ok(parsed) = SaltRef::new(refused) else {
            continue;
        };
        assert!(check_metadata_salt_ref(&parsed).is_err(), "{refused}");
    }
    for unparsable in [
        "metadata.",
        "metadata..a",
        "metadata.a.",
        "metadata.A",
        "metadata.a-b",
        &format!("metadata.{}", "a".repeat(56)),
    ] {
        assert!(SaltRef::new(unparsable).is_err(), "{unparsable}");
    }
    assert!(metadata_salt_ref("refusal", "detail").is_ok());
    assert!(metadata_salt_ref("Refusal", "detail").is_err());
    assert!(metadata_salt_ref("1refusal", "detail").is_err());
    assert!(metadata_salt_ref("refusal", "").is_err());
}

/// Every metadata `salt_ref` the A1 tables register, with each template expanded over its
/// member set.
fn registered_metadata_salt_refs() -> Vec<String> {
    let blocks: &[(&str, &[&str])] = &[
        (
            "acp",
            &[
                "authorization_parameter_hash",
                "tool_call_id",
                "capability_id",
                "authorization_receipt_id",
                "authorization_request_id",
                "authorization_tool_call_id",
                "authorization_correlation_id",
                "authorization_operation",
                "enforcement_mode",
            ],
        ),
        (
            "active_defense",
            &["action", "finding", "finding_receipt", "grant", "request"],
        ),
        ("admission_operation", &["request_binding"]),
        (
            "cage_receipt",
            &[
                "plan_digest",
                "fd_table_digest",
                "profile_digest",
                "admitted_policy_digest",
                "raw",
                "seccomp_filter_digest",
                "trace_session_digest",
                "applied_execution_identity",
                "process_id",
            ],
        ),
        ("cancellation", &["detail"]),
        (
            "child",
            &[
                "message",
                "message_sha256",
                "outcome",
                "message_truncated",
                "encoding_error_code",
                "original_payload_omitted",
                "execution_outcome",
            ],
        ),
        ("delivery_contract", &["observed_digest"]),
        ("financial", &["reported_cost_breakdown"]),
        (
            "governed_transaction",
            &[
                "approval_token_id",
                "approved_max",
                "autonomy_tier",
                "autonomy_delegation_bond_id",
                "funding_source_ref",
                "intent_hash",
                "intent_id",
                "max_amount",
                "meter_profile_hash",
                "payee_binding",
                "payer_party_id",
                "payment_token",
                "purpose",
                "quote_hash",
                "runtime_evidence_sha256",
                "runtime_verifier",
                "runtime_workload_identity",
                "seller",
                "settlement_destination",
            ],
        ),
        ("guard_error", &["detail"]),
        (
            "memory_provenance",
            &[
                "store",
                "key",
                "hash",
                "prev_hash",
                "chain_digest",
                "status",
                "reason",
                "entry_id",
                "capability_id",
                "receipt_id",
                "written_at",
            ],
        ),
        (
            "mercury",
            &[
                "workflow_id",
                "account_id",
                "desk_id",
                "strategy_id",
                "release_id",
                "rollback_id",
                "exception_id",
                "inquiry_id",
                "event_id",
                "idempotency_key",
                "causal_parent_event_ids",
                "workflow_version",
                "policy_reference",
                "model_id",
                "source_system",
                "source_record_id",
                "model_provider",
                "model_name",
                "model_version",
                "hosting_mode",
                "dependency_digest",
                "retention_class",
                "redaction_profile",
                "audience",
                "approver_subjects",
                "approval_ticket_id",
                "bundle_refs",
            ],
        ),
        ("otel", &["trace_id", "span_id"]),
        ("post_invocation", &["escalations"]),
        ("protocol_admission", &["last_error", "last_error_code"]),
        (
            "protocol_refusal",
            &["request_digest", "method_sha256", "target_sha256"],
        ),
        (
            "receipt_context",
            &["request_namespace", "authorization_resource"],
        ),
        ("refusal", &["detail"]),
        (
            "scim_lifecycle",
            &[
                "provider_id",
                "provider_record_id",
                "principal",
                "subject_key",
                "user_id",
                "user_name",
                "revoked_capability_ids",
                "entitlements",
                "receipt_kind",
            ],
        ),
        ("security_event", &["subject"]),
        (
            "session_report",
            &[
                "operation_sha256",
                "context_sha256",
                "agent_id",
                "session_anchor_id",
                "auth_epoch",
                "request_id",
                "capability_sha256",
                "execution_outcome",
            ],
        ),
        (
            "wall_authorization_context",
            &[
                "schema",
                "request_id",
                "workflow_id",
                "actor_label",
                "buyer_motion",
                "control_surface",
                "source_domain",
                "requested_domain",
                "tool_name",
                "policy_reference",
            ],
        ),
        (
            "wall_denied_access_record",
            &[
                "schema",
                "request_id",
                "workflow_id",
                "source_domain",
                "requested_domain",
                "tool_name",
                "escalation_owner",
                "support_owner",
                "note",
            ],
        ),
        (
            "wall_guard_outcome",
            &[
                "schema",
                "request_id",
                "workflow_id",
                "decision",
                "guard_name",
                "pipeline_name",
                "matched_policy",
                "evaluated_tool",
                "allowed_tools",
                "reason",
                "fail_closed",
            ],
        ),
        (
            "wall_policy_snapshot",
            &[
                "schema",
                "policy_id",
                "source_domain",
                "allowed_tools",
                "fail_closed",
                "note",
                "policy_hash",
            ],
        ),
    ];
    let call_chain_members = [
        "evidence_sources",
        "upstream_proof",
        "asserted_context",
        "continuation_token_id",
        "session_anchor_id",
        "receipt_lineage_statement_id",
        "chain_id",
        "parent_request_id",
        "parent_receipt_id",
        "origin_subject",
        "delegator_subject",
    ];
    let metered_leaves = [
        "settlement_mode",
        "quote_id",
        "provider",
        "billing_unit",
        "quoted_units",
        "quoted_cost",
        "issued_at",
        "expires_at",
        "max_billed_units",
    ];
    let metered_usage_leaves = [
        "evidence_kind",
        "evidence_id",
        "observed_units",
        "evidence_sha256",
    ];

    let mut refs = Vec::new();
    for (block, fields) in blocks {
        for field in fields.iter() {
            refs.push(format!("metadata.{block}.{field}"));
        }
    }
    for member in call_chain_members {
        refs.push(format!("metadata.governed_transaction.cc_{member}"));
    }
    for leaf in metered_leaves {
        refs.push(format!("metadata.governed_transaction.metered_{leaf}"));
    }
    for leaf in metered_usage_leaves {
        refs.push(format!(
            "metadata.governed_transaction.metered_usage_{leaf}"
        ));
    }
    for position in [0, 1, 9, 10, usize::MAX] {
        refs.push(format!("metadata.otel.attr_{position}"));
    }
    refs
}

#[test]
fn metadata_salt_refs_fit_64_bytes() {
    let refs = registered_metadata_salt_refs();
    let mut longest = "";
    for text in &refs {
        assert!(text.len() <= 64, "{text} is {} bytes", text.len());
        let parsed = SaltRef::new(text.as_str()).test_unwrap();
        assert!(check_metadata_salt_ref(&parsed).is_ok(), "{text}");
        if text.len() > longest.len() {
            longest = text;
        }
    }
    assert_eq!(
        longest,
        "metadata.governed_transaction.cc_receipt_lineage_statement_id"
    );
    assert_eq!(longest.len(), 61);
    let mut unique = refs.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(unique.len(), refs.len());
}

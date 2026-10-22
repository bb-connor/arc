#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "Test fixtures deliberately fail on violated setup invariants."
)]

use chio_core_types::receipt::evidence::{
    CapabilitySnapshot, CapabilitySnapshotProvenance, EvidenceChildReceiptScope,
    EvidenceExportQuery, EvidenceLineageReferences, EvidenceReadBoundaryError, ReceiptReadBoundary,
};

#[test]
fn evidence_lineage_references_detect_when_empty() {
    let references = EvidenceLineageReferences::default();
    assert!(references.is_empty());
    assert_eq!(
        serde_json::to_value(references).unwrap(),
        serde_json::json!({})
    );
}

#[test]
fn evidence_export_query_child_scope_reserves_time_window_context_until_lineage_joins_exist() {
    assert_eq!(
        EvidenceExportQuery {
            capability_id: Some("cap-1".to_string()),
            since: Some(10),
            ..EvidenceExportQuery::default()
        }
        .child_receipt_scope(),
        EvidenceChildReceiptScope::TimeWindowContextOnly
    );
}

#[test]
fn tenant_scoped_evidence_export_omits_child_receipts_without_join_path() {
    assert_eq!(
        EvidenceExportQuery::tenant_scoped("tenant-a").child_receipt_scope(),
        EvidenceChildReceiptScope::OmittedNoJoinPath
    );
}

#[test]
fn evidence_export_query_allows_admin_all_with_tenant_filter() {
    EvidenceExportQuery {
        tenant: Some("tenant-a".to_string()),
        read_boundary: Some(ReceiptReadBoundary::AdminAll),
        ..EvidenceExportQuery::default()
    }
    .validate_read_boundary()
    .expect("admin-all evidence export may narrow to a tenant filter");
}

#[test]
fn evidence_export_query_requires_explicit_read_boundary() {
    let err = EvidenceExportQuery::default()
        .validate_read_boundary()
        .expect_err("missing read boundary must fail closed");

    assert_eq!(
        err,
        EvidenceReadBoundaryError(
            "evidence export requires an explicit receipt read boundary".to_string()
        )
    );
    assert_eq!(
        err.to_string(),
        "receipt read boundary error: evidence export requires an explicit receipt read boundary"
    );
}

#[test]
fn evidence_export_query_rejects_empty_admin_tenant_filter() {
    let err = EvidenceExportQuery {
        tenant: Some("   ".to_string()),
        read_boundary: Some(ReceiptReadBoundary::AdminAll),
        ..EvidenceExportQuery::default()
    }
    .validate_read_boundary()
    .expect_err("blank admin tenant filter must fail closed");

    assert_eq!(
        err.0,
        "admin-all evidence export tenant filter requires a non-empty tenant"
    );
}

#[test]
fn evidence_export_query_rejects_empty_tenant_scoped_boundary() {
    let err = EvidenceExportQuery::tenant_scoped("   ")
        .validate_read_boundary()
        .expect_err("blank tenant-scoped boundary must fail closed");

    assert_eq!(
        err.0,
        "tenant-scoped evidence export requires a non-empty tenant"
    );
}

#[test]
fn evidence_export_query_rejects_tenant_scoped_boundary_mismatch() {
    let err = EvidenceExportQuery {
        tenant: Some("tenant-a".to_string()),
        read_boundary: Some(ReceiptReadBoundary::TenantScoped {
            tenant: "tenant-b".to_string(),
        }),
        ..EvidenceExportQuery::default()
    }
    .validate_read_boundary()
    .expect_err("tenant-scoped boundary must match query tenant");

    assert_eq!(
        err.0,
        "tenant-scoped evidence export tenant does not match query tenant"
    );
}

#[test]
fn evidence_export_query_normalizes_tenant_from_scoped_boundary() {
    let normalized = EvidenceExportQuery {
        tenant: None,
        read_boundary: Some(ReceiptReadBoundary::TenantScoped {
            tenant: "tenant-a".to_string(),
        }),
        ..EvidenceExportQuery::default()
    }
    .normalized_for_read_boundary();

    assert_eq!(normalized.tenant.as_deref(), Some("tenant-a"));
}

#[test]
fn admin_all_tenant_filtered_export_omits_child_receipts_without_join_path() {
    assert_eq!(
        EvidenceExportQuery {
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
            ..EvidenceExportQuery::default()
        }
        .child_receipt_scope(),
        EvidenceChildReceiptScope::OmittedNoJoinPath
    );
}

fn unsigned_snapshot_json() -> serde_json::Value {
    serde_json::json!({
        "capability_id": "capability",
        "subject_key": "subject",
        "issuer_key": "issuer",
        "issued_at": 1,
        "expires_at": 2,
        "grants_json": "{}",
        "delegation_depth": 0,
        "parent_capability_id": null
    })
}

#[test]
fn snapshot_without_provenance_is_refused() {
    let error = serde_json::from_value::<CapabilitySnapshot>(unsigned_snapshot_json())
        .err()
        .map(|error| error.to_string());
    assert_eq!(error.as_deref(), Some("missing field `provenance`"));
}

#[test]
fn unsigned_projection_provenance_is_refused() {
    let mut value = unsigned_snapshot_json();
    value["provenance"] = serde_json::json!("legacy_projection");
    let error = serde_json::from_value::<CapabilitySnapshot>(value)
        .err()
        .map(|error| error.to_string());
    assert_eq!(
        error.as_deref(),
        Some("unknown variant `legacy_projection`, expected `signed_token` or `synthetic_anchor`")
    );
    assert_eq!(
        "legacy_projection".parse::<CapabilitySnapshotProvenance>(),
        Err("unsupported capability snapshot provenance \"legacy_projection\"".to_string())
    );
}

#[test]
fn evidence_and_checkpoint_identifiers_are_pinned() {
    use chio_core_types::receipt::checkpoint::{
        CHECKPOINT_CONSISTENCY_PROOF_SCHEMA, CHECKPOINT_EQUIVOCATION_SCHEMA,
        CHECKPOINT_PUBLICATION_SCHEMA, CHECKPOINT_SCHEMA, CHECKPOINT_WITNESS_SCHEMA,
    };
    use chio_core_types::receipt::evidence::{
        EVIDENCE_DISCLOSURE_NOTICE_SCHEMA, EVIDENCE_EXPORT_COMMITMENT_SCHEMA,
        EVIDENCE_EXPORT_MANIFEST_SCHEMA, EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA,
        FEDERATED_EVIDENCE_SHARE_SCHEMA, FEDERATION_POLICY_SCHEMA,
    };
    use chio_core_types::root_authority::CHIO_VERIFIER_TRUST_SCHEMA;

    for (constant, literal) in [
        (CHECKPOINT_SCHEMA, "chio.checkpoint_statement.v1"),
        (
            CHECKPOINT_PUBLICATION_SCHEMA,
            "chio.checkpoint_publication.v1",
        ),
        (CHECKPOINT_WITNESS_SCHEMA, "chio.checkpoint_witness.v1"),
        (
            CHECKPOINT_CONSISTENCY_PROOF_SCHEMA,
            "chio.checkpoint_consistency_proof.v1",
        ),
        (
            CHECKPOINT_EQUIVOCATION_SCHEMA,
            "chio.checkpoint_equivocation.v1",
        ),
        (
            EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA,
            "chio.evidence_transparency_claims.v1",
        ),
        (
            EVIDENCE_EXPORT_MANIFEST_SCHEMA,
            "chio.evidence_export_manifest.v1",
        ),
        (
            EVIDENCE_EXPORT_COMMITMENT_SCHEMA,
            "chio.evidence_export_commitment.v1",
        ),
        (
            EVIDENCE_DISCLOSURE_NOTICE_SCHEMA,
            "chio.evidence_export_disclosure_notice.v1",
        ),
        (FEDERATION_POLICY_SCHEMA, "chio.federation-policy.v1"),
        (
            FEDERATED_EVIDENCE_SHARE_SCHEMA,
            "chio.federated-evidence-share.v1",
        ),
        (CHIO_VERIFIER_TRUST_SCHEMA, "chio.verifier-trust.v1"),
    ] {
        assert_eq!(constant, literal);
    }
}

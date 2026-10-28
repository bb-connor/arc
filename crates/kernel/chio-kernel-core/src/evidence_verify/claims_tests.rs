//! Tests for audit and transparency-preview claims.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::evidence::{
    EvidenceChildReceiptScope, EvidenceExportQuery, EvidenceRetentionMetadata,
};

use super::*;
use crate::evidence_verify::tests::{build_checkpoint, build_checkpoint_with_previous};
use crate::evidence_verify::{
    build_checkpoint_transparency, build_trust_anchored_checkpoint_publication,
    checkpoint_chain_leaf_hash,
};

#[test]
fn evidence_export_marks_unanchored_publication_as_transparency_preview() {
    let keypair = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &keypair)
        .expect("first checkpoint");
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        &keypair,
        Some(&first),
        &[checkpoint_chain_leaf_hash(&first.body).expect("first chain leaf")],
    )
    .expect("second checkpoint");
    let bundle = EvidenceExportBundle {
        query: EvidenceExportQuery::default(),
        tool_receipts: Vec::new(),
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::FullQueryWindow,
        checkpoints: vec![first.clone(), second.clone()],
        capability_lineage: Vec::new(),
        inclusion_proofs: Vec::new(),
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: Some(0),
            oldest_live_receipt_timestamp: None,
        },
    };
    let transparency =
        build_checkpoint_transparency(&[first, second]).expect("transparency summary");

    let claims = build_evidence_transparency_claims(&bundle, &transparency, None);
    assert_eq!(
        claims.publication_state,
        EvidencePublicationState::TransparencyPreview
    );
    assert!(claims.trust_anchor.is_none());
    assert_eq!(claims.audit.signed_checkpoints, 2);
    assert_eq!(claims.audit.checkpoint_consistency_proofs, 1);
    assert_eq!(claims.transparency_preview.len(), 1);
    assert_eq!(
        claims.transparency_preview[0].claim,
        "append_only_local_checkpoint_log"
    );
    assert_eq!(claims.transparency_preview[0].log_tree_size, 4);

    let anchored_claims =
        build_evidence_transparency_claims(&bundle, &transparency, Some("witness-root"));
    assert_eq!(
        anchored_claims.publication_state,
        EvidencePublicationState::TransparencyPreview
    );
    assert!(anchored_claims.trust_anchor.is_none());
    assert_eq!(anchored_claims.transparency_preview.len(), 1);
}

#[test]
fn evidence_export_marks_bound_publication_as_trust_anchored() {
    let keypair = Keypair::generate();
    let first = build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], &keypair)
        .expect("first checkpoint");
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        &keypair,
        Some(&first),
        &[checkpoint_chain_leaf_hash(&first.body).expect("first chain leaf")],
    )
    .expect("second checkpoint");
    let bundle = EvidenceExportBundle {
        query: EvidenceExportQuery::default(),
        tool_receipts: Vec::new(),
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::FullQueryWindow,
        checkpoints: vec![first.clone(), second.clone()],
        capability_lineage: Vec::new(),
        inclusion_proofs: Vec::new(),
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: Some(0),
            oldest_live_receipt_timestamp: None,
        },
    };
    let mut transparency =
        build_checkpoint_transparency(&[first.clone(), second.clone()]).expect("summary");
    let binding = chio_core_types::receipt::checkpoint::CheckpointPublicationTrustAnchorBinding {
        publication_identity: chio_core_types::receipt::checkpoint::CheckpointPublicationIdentity::new(
            chio_core_types::receipt::checkpoint::CheckpointPublicationIdentityKind::LocalLog,
            transparency.publications[0].log_id.clone(),
        ),
        trust_anchor_identity: chio_core_types::receipt::checkpoint::CheckpointTrustAnchorIdentity::new(
            chio_core_types::receipt::checkpoint::CheckpointTrustAnchorIdentityKind::TransparencyRoot,
            "root-set-1",
        ),
        trust_anchor_ref: "witness-root".to_string(),
        signer_cert_ref: "cert-chain-1".to_string(),
        publication_profile_version: "phase4-pilot".to_string(),
    };
    transparency.publications = vec![
        build_trust_anchored_checkpoint_publication(&first, binding.clone())
            .expect("first anchored publication"),
        build_trust_anchored_checkpoint_publication(&second, binding)
            .expect("second anchored publication"),
    ];

    let unpinned = build_evidence_transparency_claims(&bundle, &transparency, None);
    assert_ne!(
        unpinned.publication_state,
        EvidencePublicationState::TrustAnchored
    );
    assert_eq!(unpinned.trust_anchor, None);
    let anchored_claims =
        build_evidence_transparency_claims(&bundle, &transparency, Some("witness-root"));
    assert_eq!(
        anchored_claims.publication_state,
        EvidencePublicationState::TrustAnchored
    );
    assert_eq!(
        anchored_claims.trust_anchor.as_deref(),
        Some("witness-root")
    );
    assert!(anchored_claims.transparency_preview.is_empty());
}

#[test]
fn evidence_transparency_claims_reject_invalid_publication_state_combinations() {
    let anchored_without_anchor = EvidenceTransparencyClaims {
        schema: EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA.to_string(),
        publication_state: EvidencePublicationState::TrustAnchored,
        trust_anchor: None,
        audit: EvidenceAuditClaims {
            checkpoint_logs: Vec::new(),
            signed_checkpoints: 0,
            checkpoint_publications: 0,
            checkpoint_witnesses: 0,
            checkpoint_consistency_proofs: 0,
            inclusion_proofs: 0,
            capability_lineage_records: 0,
        },
        transparency_preview: Vec::new(),
    };
    assert!(anchored_without_anchor
        .validate()
        .unwrap_err()
        .contains("trust_anchor"));
}

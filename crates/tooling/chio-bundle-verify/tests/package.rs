//! Package verification refusals: pinned signers, signed manifest and
//! payload, inventory, file reads, scope, proofs, transparency, trust-anchor
//! binding and the disclosure notice.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use chio_bundle_verify::package::{sign_envelope, verify_inventory};
use chio_bundle_verify::read::{read_bytes, MAX_FILE_BYTES};
use chio_bundle_verify::verify::{
    read_package, verify_checkpoints, verify_decoded_package, verify_disclosure_notice,
    verify_inclusion_proofs, verify_manifest_counts, verify_package, verify_query_scope,
    verify_tool_receipts, verify_transparency, verify_transparency_claim_boundary,
};
use chio_bundle_verify::{BundleVerifyErrorKind, ExitClass};
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::receipt::body::ChioReceipt;
use chio_core_types::receipt::checkpoint::{
    CheckpointPublicationIdentity, CheckpointPublicationIdentityKind,
    CheckpointPublicationTrustAnchorBinding, CheckpointTrustAnchorIdentity,
    CheckpointTrustAnchorIdentityKind,
};
use chio_core_types::receipt::evidence::{
    EvidenceAuditClaims, EvidenceChildReceiptScope, EvidenceExportBundle, EvidenceExportQuery,
    EvidenceImportPackage, EvidencePublicationState, EvidenceRetentionMetadata,
    EvidenceToolReceiptRecord, EvidenceTransparencyClaims, EvidenceUncheckpointedReceipt,
    ExportCommitment, ReceiptReadBoundary, EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA,
};
use chio_core_types::receipt::kinds::{
    BoundaryClass, ObservationOutcome, ReceiptKind, ToolOrigin, TrustLevel,
};
use chio_core_types::receipt::lineage::SignedExportEnvelope;
use chio_kernel_core::evidence_verify::{
    build_evidence_transparency_claims, build_trust_anchored_checkpoint_publication,
    checkpoint_chain_leaf_hash, checkpoint_log_id,
};
use chio_test_support::prelude::*;
use support::*;

fn fixture() -> (tempfile::TempDir, EvidenceImportPackage) {
    let directory = tempfile::tempdir().test_unwrap();
    write(directory.path(), &sample_bundle(), &package_keypair());
    let package = verify_package(directory.path(), &package_trust(), None)
        .test_unwrap()
        .package;
    (directory, package)
}

fn resign(package: &mut EvidenceImportPackage) {
    package.envelope = sign_envelope(
        &package.manifest,
        &package.bundle,
        package.transparency.as_ref(),
        None,
        &package_keypair(),
    )
    .test_unwrap();
}

fn anchor_binding(log_id: String) -> CheckpointPublicationTrustAnchorBinding {
    CheckpointPublicationTrustAnchorBinding {
        publication_identity: CheckpointPublicationIdentity::new(
            CheckpointPublicationIdentityKind::LocalLog,
            log_id,
        ),
        trust_anchor_identity: CheckpointTrustAnchorIdentity::new(
            CheckpointTrustAnchorIdentityKind::TransparencyRoot,
            "root-set-1",
        ),
        trust_anchor_ref: "anchor-root-1".to_string(),
        signer_cert_ref: "cert-chain-1".to_string(),
        publication_profile_version: "profile-1".to_string(),
    }
}

#[test]
fn package_round_trips_under_its_pinned_kernel_key() {
    let (_directory, package) = fixture();
    assert_eq!(package.bundle.tool_receipts.len(), 1);
    assert_eq!(package.manifest.receipt_semantics.authorized, 1);
}

#[test]
fn package_rejects_receipt_checkpoint_signer_substitution() {
    let mut bundle = sample_bundle();
    let bytes = canonical_json_bytes(&bundle.tool_receipts[0].receipt).test_unwrap();
    let foreign = Keypair::generate();
    bundle.checkpoints[0] = build_checkpoint(1, 1, 1, &[bytes], &foreign).test_unwrap();
    let receipts = verify_tool_receipts(&bundle.tool_receipts, None).test_unwrap();
    let trust = trust_for(vec![package_keypair().public_key(), foreign.public_key()]);
    let checkpoints = verify_checkpoints(&bundle.checkpoints, &trust).test_unwrap();
    let error = verify_inclusion_proofs(&receipts, &checkpoints, &bundle.inclusion_proofs, 0)
        .test_unwrap_err();
    assert!(error.message().contains("signer"), "{error}");
}

#[test]
fn package_rejects_unsigned_manifest() {
    let directory = tempfile::tempdir().test_unwrap();
    write(directory.path(), &sample_bundle(), &package_keypair());
    fs::remove_file(directory.path().join("export-envelope.json")).test_unwrap();
    let error = verify_package(directory.path(), &package_trust(), None).test_unwrap_err();
    assert_eq!(error.kind(), BundleVerifyErrorKind::EnvelopeInvalid);
    assert!(error.message().contains("envelope"), "{error}");
}

#[test]
fn package_rejects_fresh_key_even_when_every_signature_is_valid() {
    let (directory, _) = fixture();
    let trust = trust_for(vec![Keypair::generate().public_key()]);
    let error = verify_package(directory.path(), &trust, None).test_unwrap_err();
    assert!(error.message().contains("trusted kernel key"), "{error}");
    assert_eq!(error.exit_class(), ExitClass::VerifierContext);
}

#[test]
fn package_remote_payload_cannot_differ_from_signed_files() {
    let (_directory, mut package) = fixture();
    package.bundle.retention.oldest_live_receipt_timestamp = Some(999);
    let error = verify_decoded_package(&package, &package_trust(), None).test_unwrap_err();
    assert!(error.message().contains("payload"), "{error}");
    assert_eq!(error.exit_class(), ExitClass::Integrity);
}

#[test]
fn package_signed_manifest_cannot_omit_consumed_files() {
    let (_directory, mut package) = fixture();
    package
        .manifest
        .files
        .retain(|file| file.path != "receipts.ndjson");
    resign(&mut package);
    let error = verify_decoded_package(&package, &package_trust(), None).test_unwrap_err();
    assert!(error.message().contains("every package file"), "{error}");
}

#[test]
fn package_rejects_foreign_receipt_even_when_manifest_signer_is_trusted() {
    let (_directory, mut package) = fixture();
    package.bundle.tool_receipts[0].receipt = sample_receipt();
    resign(&mut package);
    let error = verify_decoded_package(&package, &package_trust(), None).test_unwrap_err();
    assert!(error.message().contains("trusted kernel key"), "{error}");
}

#[test]
fn package_rejects_manifest_rewrite_without_a_new_signature() {
    let (directory, mut package) = fixture();
    package.manifest.exported_at += 1;
    fs::write(
        directory.path().join("manifest.json"),
        serde_json::to_vec(&package.manifest).test_unwrap(),
    )
    .test_unwrap();
    let error = verify_package(directory.path(), &package_trust(), None).test_unwrap_err();
    assert!(error.message().contains("manifest"), "{error}");
}

#[test]
fn package_accepts_explicit_rotation_keys_and_preserves_uncheckpointed_observations() {
    let directory = tempfile::tempdir().test_unwrap();
    let signer = Keypair::generate();
    let mut bundle = sample_bundle();
    let mut body = bundle.tool_receipts[0].receipt.body();
    body.decision = None;
    body.receipt_kind = ReceiptKind::AdvisoryEvaluation;
    body.boundary_class = BoundaryClass::AdvisoryOnly;
    body.observation_outcome = Some(ObservationOutcome::Observed);
    body.trust_level = TrustLevel::Advisory;
    body.tool_origin = ToolOrigin::HostExecutedUnmediated;
    bundle.tool_receipts[0].receipt = ChioReceipt::sign(body, &package_keypair()).test_unwrap();
    bundle.checkpoints.clear();
    bundle.inclusion_proofs.clear();
    bundle.uncheckpointed_receipts = vec![EvidenceUncheckpointedReceipt {
        seq: 1,
        receipt_id: bundle.tool_receipts[0].receipt.id.clone(),
    }];
    write(directory.path(), &bundle, &signer);
    let trust = trust_for(vec![signer.public_key(), package_keypair().public_key()]);
    let verified = verify_package(directory.path(), &trust, None).test_unwrap();
    assert_eq!(verified.package.bundle.uncheckpointed_receipts.len(), 1);
    assert_eq!(verified.package.manifest.receipt_semantics.authorized, 0);
    assert_eq!(verified.package.manifest.counts.uncheckpointed_receipts, 1);
    assert!(!verified
        .package
        .manifest
        .claim_boundary
        .test_unwrap()
        .is_trust_anchored());
}

#[test]
fn package_envelope_wire_shape_and_domain_are_pinned() {
    let (_directory, mut package) = fixture();
    let wire = serde_json::to_value(&package.envelope).test_unwrap();
    assert_eq!(wire["body"]["schema"], "chio.evidence_export_commitment.v1");
    let fields = wire
        .as_object()
        .test_unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(fields, BTreeSet::from(["body", "signature", "signerKey"]));
    let mut body = wire["body"].clone();
    let fields = body
        .as_object()
        .test_unwrap()
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        fields,
        BTreeSet::from(["manifestSha256", "payloadSha256", "schema"])
    );
    body["schema"] = "chio.other_commitment.v1".into();
    package.envelope = SignedExportEnvelope::sign(
        serde_json::from_value::<ExportCommitment>(body).test_unwrap(),
        &package_keypair(),
    )
    .test_unwrap();
    let error = verify_decoded_package(&package, &package_trust(), None).test_unwrap_err();
    assert!(error.message().contains("schema"), "{error}");
}

#[test]
fn package_rejects_duplicate_inventory_and_oversized_file_commitment() {
    let (_directory, package) = fixture();
    let mut duplicate = package.manifest.clone();
    duplicate.files.push(duplicate.files[0].clone());
    let error = verify_inventory(&duplicate).test_unwrap_err();
    assert!(error.message().contains("exactly once"), "{error}");

    let mut oversized = package.manifest;
    oversized.files[0].bytes = u64::try_from(MAX_FILE_BYTES).test_unwrap() + 1;
    let error = verify_inventory(&oversized).test_unwrap_err();
    assert!(error.message().contains("byte limit"), "{error}");
}

#[test]
fn package_rejects_duplicate_manifest_fields() {
    let (directory, package) = fixture();
    let mut manifest = serde_json::to_string(&package.manifest).test_unwrap();
    manifest.insert_str(1, "\"schema\":\"chio.evidence_export_manifest.v1\",");
    fs::write(directory.path().join("manifest.json"), manifest).test_unwrap();
    let error = read_package(directory.path()).test_unwrap_err();
    assert_eq!(
        error.signed_json_source().map(|source| source.code()),
        Some("urn:chio:error:attest:signed-json-invalid-input")
    );
    assert_eq!(error.exit_class(), ExitClass::ParseOrSchema);
}

#[test]
fn package_rejects_a_record_member_its_schema_would_drop() {
    let (directory, _) = fixture();
    let path = directory.path().join("retention.json");
    let mut retention: serde_json::Value =
        serde_json::from_slice(&fs::read(&path).test_unwrap()).test_unwrap();
    retention["unsignedHint"] = serde_json::json!(true);
    fs::write(&path, serde_json::to_vec(&retention).test_unwrap()).test_unwrap();
    let error = read_package(directory.path()).test_unwrap_err();
    assert!(
        matches!(
            error.kind(),
            BundleVerifyErrorKind::FileHashMismatch | BundleVerifyErrorKind::SchemaInvalid
        ),
        "{error}"
    );
}

#[test]
fn package_reader_rejects_non_regular_and_oversized_inputs() {
    let directory = tempfile::tempdir().test_unwrap();
    fs::create_dir(directory.path().join("directory.json")).test_unwrap();
    let error = read_bytes(directory.path(), "directory.json").test_unwrap_err();
    assert!(error.message().contains("regular file"), "{error}");
    let file = fs::File::create(directory.path().join("large.json")).test_unwrap();
    file.set_len(u64::try_from(MAX_FILE_BYTES).test_unwrap() + 1)
        .test_unwrap();
    let error = read_bytes(directory.path(), "large.json").test_unwrap_err();
    assert!(error.message().contains("byte limit"), "{error}");
}

#[cfg(unix)]
#[test]
fn package_reader_rejects_leaf_and_parent_symlinks_and_fifo() {
    use std::os::unix::fs::{symlink, FileTypeExt};
    let directory = tempfile::tempdir().test_unwrap();
    let outside = tempfile::tempdir().test_unwrap();
    fs::write(outside.path().join("file.json"), b"{}").test_unwrap();
    symlink(
        outside.path().join("file.json"),
        directory.path().join("leaf.json"),
    )
    .test_unwrap();
    symlink(outside.path(), directory.path().join("parent")).test_unwrap();
    for name in [
        "leaf.json",
        "parent/file.json",
        "../file.json",
        "/file.json",
    ] {
        if let Ok(bytes) = read_bytes(directory.path(), name) {
            panic!("untrusted path {name} was followed: {bytes:?}");
        }
    }
    let fifo = directory.path().join("fifo");
    let created = std::process::Command::new("mkfifo")
        .args(["-m", "600"])
        .arg(&fifo)
        .status()
        .test_unwrap();
    assert!(created.success(), "private FIFO fixture creation failed");
    assert!(fs::symlink_metadata(&fifo)
        .test_unwrap()
        .file_type()
        .is_fifo());
    let error = read_bytes(directory.path(), "fifo").test_unwrap_err();
    assert!(error.message().contains("regular file"), "{error}");
}

#[test]
fn manifest_count_verification_rejects_semantic_drift() {
    let bundle = sample_bundle();
    let mut manifest = manifest_for_bundle(&bundle);
    manifest.receipt_semantics.authorized = 0;
    let error = verify_manifest_counts(&manifest, &bundle).test_unwrap_err();
    assert!(error.message().contains("semantic summary"), "{error}");
}

fn tenant_receipts(tenant: &str) -> Vec<EvidenceToolReceiptRecord> {
    let mut receipt = sample_receipt();
    receipt.tenant_id = Some(tenant.to_string());
    vec![EvidenceToolReceiptRecord { seq: 1, receipt }]
}

#[test]
fn query_scope_rejects_tenant_scoped_package_with_mixed_receipt_tenant() {
    let error = verify_query_scope(
        &EvidenceExportQuery {
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
            ..EvidenceExportQuery::default()
        },
        &tenant_receipts("tenant-b"),
        &[],
        EvidenceChildReceiptScope::OmittedNoJoinPath,
        &BTreeMap::new(),
    )
    .test_unwrap_err();
    assert!(
        error.message().contains("outside tenant scope tenant-a"),
        "{error}"
    );
}

#[test]
fn query_scope_rejects_admin_tenant_filtered_package_with_mixed_receipt_tenant() {
    let error = verify_query_scope(
        &EvidenceExportQuery {
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
            ..EvidenceExportQuery::default()
        },
        &tenant_receipts("tenant-b"),
        &[],
        EvidenceChildReceiptScope::OmittedNoJoinPath,
        &BTreeMap::new(),
    )
    .test_unwrap_err();
    assert!(
        error.message().contains("outside tenant scope tenant-a"),
        "{error}"
    );
}

#[test]
fn import_package_requires_explicit_read_boundary() {
    let mut bundle = sample_bundle();
    bundle.query = EvidenceExportQuery::default();
    let manifest = manifest_for_bundle(&bundle);
    let envelope = sign_envelope(&manifest, &bundle, None, None, &package_keypair()).test_unwrap();
    let package = EvidenceImportPackage {
        manifest,
        bundle,
        transparency: None,
        federation_policy: None,
        envelope,
    };
    let error = verify_decoded_package(&package, &package_trust(), None).test_unwrap_err();
    assert!(error.message().contains("read boundary"), "{error}");
}

fn two_checkpoints(
    keypair: &Keypair,
) -> Vec<chio_core_types::receipt::checkpoint::KernelCheckpoint> {
    let first =
        build_checkpoint(1, 1, 2, &[b"one".to_vec(), b"two".to_vec()], keypair).test_unwrap();
    let second = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"three".to_vec(), b"four".to_vec()],
        keypair,
        Some(&first),
        &[checkpoint_chain_leaf_hash(&first.body).test_unwrap()],
    )
    .test_unwrap();
    vec![first, second]
}

#[test]
fn checkpoint_transparency_records_match_derived_chain() {
    let checkpoints = two_checkpoints(&Keypair::generate());
    let summary = verify_transparency(&checkpoints, None).test_unwrap();
    verify_transparency(&checkpoints, Some(&summary)).test_unwrap();
}

#[test]
fn checkpoint_transparency_verification_fails_closed_on_duplicate_checkpoint_fork() {
    let keypair = Keypair::generate();
    let mut checkpoints = two_checkpoints(&keypair);
    let fork = build_checkpoint_with_previous(
        2,
        3,
        4,
        &[b"five".to_vec(), b"six".to_vec()],
        &keypair,
        Some(&checkpoints[0]),
        &[checkpoint_chain_leaf_hash(&checkpoints[0].body).test_unwrap()],
    )
    .test_unwrap();
    checkpoints.push(fork);
    let error = verify_transparency(&checkpoints, None).test_unwrap_err();
    assert!(
        error.message().contains("duplicate checkpoint sequence 2"),
        "{error}"
    );
}

fn anchored_claims(bundle: &EvidenceExportBundle) -> EvidenceTransparencyClaims {
    let transparency = verify_transparency(&bundle.checkpoints, None).test_unwrap();
    let count = |len: usize| u64::try_from(len).test_unwrap();
    EvidenceTransparencyClaims {
        schema: EVIDENCE_TRANSPARENCY_CLAIMS_SCHEMA.to_string(),
        publication_state: EvidencePublicationState::TrustAnchored,
        trust_anchor: Some("anchor-root-1".to_string()),
        audit: EvidenceAuditClaims {
            checkpoint_logs: transparency
                .publications
                .iter()
                .map(|publication| publication.log_id.clone())
                .collect(),
            signed_checkpoints: count(bundle.checkpoints.len()),
            checkpoint_publications: count(transparency.publications.len()),
            checkpoint_witnesses: count(transparency.witnesses.len()),
            checkpoint_consistency_proofs: count(transparency.consistency_proofs.len()),
            inclusion_proofs: count(bundle.inclusion_proofs.len()),
            capability_lineage_records: count(bundle.capability_lineage.len()),
        },
        transparency_preview: Vec::new(),
    }
}

#[test]
fn anchored_transparency_claims_fail_closed_during_export_verification() {
    let bundle = sample_bundle();
    let transparency = verify_transparency(&bundle.checkpoints, None).test_unwrap();
    let error =
        verify_transparency_claim_boundary(Some(&anchored_claims(&bundle)), &bundle, &transparency)
            .test_unwrap_err();
    assert!(
        error.message().contains("claim boundary does not match"),
        "{error}"
    );
}

#[test]
fn invalid_transparency_claim_boundary_is_an_integrity_failure() {
    let bundle = sample_bundle();
    let transparency = verify_transparency(&bundle.checkpoints, None).test_unwrap();
    let mut claims = build_evidence_transparency_claims(&bundle, &transparency, None);
    claims.schema = "invalid-schema".to_string();
    let error =
        verify_transparency_claim_boundary(Some(&claims), &bundle, &transparency).test_unwrap_err();
    assert_eq!(error.kind(), BundleVerifyErrorKind::EvidenceInconsistent);
    assert_eq!(error.exit_class(), ExitClass::Integrity);
}

fn bound_transparency(
    bundle: &EvidenceExportBundle,
) -> (
    chio_core_types::receipt::checkpoint::CheckpointTransparencySummary,
    CheckpointPublicationTrustAnchorBinding,
) {
    let checkpoint = bundle.checkpoints.first().cloned().test_unwrap();
    let mut transparency = verify_transparency(&bundle.checkpoints, None).test_unwrap();
    let binding = anchor_binding(checkpoint_log_id(&checkpoint));
    transparency.publications =
        vec![
            build_trust_anchored_checkpoint_publication(&checkpoint, binding.clone()).test_unwrap(),
        ];
    (transparency, binding)
}

#[test]
fn self_declared_anchor_does_not_qualify_manifest_claims() {
    let bundle = sample_bundle();
    let (transparency, _) = bound_transparency(&bundle);
    let anchored =
        build_evidence_transparency_claims(&bundle, &transparency, Some("anchor-root-1"));
    verify_transparency(&bundle.checkpoints, Some(&transparency)).test_unwrap();
    let error = verify_transparency_claim_boundary(Some(&anchored), &bundle, &transparency)
        .test_unwrap_err();
    assert!(error.message().contains("claim boundary"), "{error}");
}

#[test]
fn evidence_export_fails_closed_on_stale_or_missing_publication() {
    let bundle = sample_bundle();
    let (transparency, _) = bound_transparency(&bundle);
    let anchored =
        build_evidence_transparency_claims(&bundle, &transparency, Some("anchor-root-1"));
    let missing_publication = verify_transparency(&bundle.checkpoints, None).test_unwrap();
    let error = verify_transparency_claim_boundary(Some(&anchored), &bundle, &missing_publication)
        .test_unwrap_err();
    assert!(
        error.message().contains("claim boundary does not match"),
        "{error}"
    );

    let mut stale = transparency.clone();
    stale.publications[0].log_tree_size += 1;
    let error = verify_transparency(&bundle.checkpoints, Some(&stale)).test_unwrap_err();
    assert!(
        error
            .message()
            .contains("checkpoint transparency verification failed"),
        "{error}"
    );
}

#[test]
fn trust_file_anchor_qualifies_only_an_exactly_bound_publication_set() {
    let bundle = sample_bundle();
    let (transparency, binding) = bound_transparency(&bundle);
    let directory = tempfile::tempdir().test_unwrap();
    write_with_transparency(directory.path(), &bundle, &transparency, &package_keypair());

    let unanchored = verify_package(directory.path(), &package_trust(), None).test_unwrap();
    assert_eq!(
        unanchored.claims.publication_state,
        EvidencePublicationState::TransparencyPreview
    );

    let mut trust = package_trust();
    trust.checkpoint_trust_anchor = Some(binding.clone());
    let anchored = verify_package(directory.path(), &trust, None).test_unwrap();
    assert_eq!(
        anchored.claims.publication_state,
        EvidencePublicationState::TrustAnchored
    );
    assert_eq!(
        anchored.claims.trust_anchor.as_deref(),
        Some("anchor-root-1")
    );

    let mut wrong = binding;
    wrong.signer_cert_ref = "another-certificate".to_string();
    trust.checkpoint_trust_anchor = Some(wrong);
    let error = verify_package(directory.path(), &trust, None).test_unwrap_err();
    assert!(error.message().contains("anchor"), "{error}");
}

#[test]
fn trust_file_anchor_refuses_an_unbound_publication_set() {
    let directory = tempfile::tempdir().test_unwrap();
    let bundle = sample_bundle();
    write(directory.path(), &bundle, &package_keypair());
    let mut trust = package_trust();
    trust.checkpoint_trust_anchor = Some(anchor_binding(checkpoint_log_id(
        bundle.checkpoints.first().test_unwrap(),
    )));
    let error = verify_package(directory.path(), &trust, None).test_unwrap_err();
    assert!(error.message().contains("trust anchor"), "{error}");
}

fn empty_bundle(query: EvidenceExportQuery) -> EvidenceExportBundle {
    EvidenceExportBundle {
        query,
        tool_receipts: Vec::new(),
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
        checkpoints: Vec::new(),
        capability_lineage: Vec::new(),
        inclusion_proofs: Vec::new(),
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: None,
            oldest_live_receipt_timestamp: None,
        },
    }
}

#[test]
fn verify_disclosure_notice_rejects_stripped_tenant_notice() {
    let mut manifest = manifest_for_bundle(&empty_bundle(EvidenceExportQuery::tenant_scoped(
        "tenant-a",
    )));
    assert!(manifest.disclosure_notice.is_some());
    manifest.disclosure_notice = None;
    let error = verify_disclosure_notice(&manifest).test_unwrap_err();
    assert!(error.message().contains("disclosure notice"), "{error}");
}

#[test]
fn verify_disclosure_notice_rejects_admin_all_with_spurious_notice() {
    let mut manifest = manifest_for_bundle(&empty_bundle(EvidenceExportQuery::admin_all()));
    manifest.disclosure_notice =
        Some(chio_core_types::receipt::evidence::EvidenceDisclosureNotice::tenant_scoped());
    let error = verify_disclosure_notice(&manifest).test_unwrap_err();
    assert!(error.message().contains("admin-all"), "{error}");
}

#[test]
fn verify_disclosure_notice_rejects_tampered_notice() {
    let mut manifest = manifest_for_bundle(&empty_bundle(EvidenceExportQuery::tenant_scoped(
        "tenant-a",
    )));
    if let Some(notice) = manifest.disclosure_notice.as_mut() {
        notice.disclosed_checkpoint_body_fields.clear();
    }
    let error = verify_disclosure_notice(&manifest).test_unwrap_err();
    assert!(error.message().contains("disclosure notice"), "{error}");
}

#[test]
fn tenant_scoped_disclosure_notice_names_the_shared_batch_fields() {
    let notice = chio_core_types::receipt::evidence::EvidenceDisclosureNotice::for_query(
        &EvidenceExportQuery::tenant_scoped("tenant-a"),
    )
    .test_unwrap();
    assert_eq!(
        notice.schema,
        chio_core_types::receipt::evidence::EVIDENCE_DISCLOSURE_NOTICE_SCHEMA
    );
    for required in [
        "batch_start_seq",
        "batch_end_seq",
        "tree_size",
        "merkle_root",
    ] {
        assert!(notice
            .disclosed_checkpoint_body_fields
            .iter()
            .any(|field| field == required));
    }
    for required in ["entry_start_seq", "entry_end_seq", "log_tree_size"] {
        assert!(notice
            .disclosed_publication_fields
            .iter()
            .any(|field| field == required));
    }
    assert!(!notice.narrowed_metadata.is_empty());
    assert!(
        chio_core_types::receipt::evidence::EvidenceDisclosureNotice::for_query(
            &EvidenceExportQuery::admin_all()
        )
        .is_none()
    );
}

#[test]
fn receipt_embedding_an_http_receipt_needs_an_embedded_verifier() {
    let keypair = package_keypair();
    let mut body = sample_receipt_with_key(&keypair).body();
    body.metadata = Some(serde_json::json!({"chio_http_receipt_v1": {"id": "http-1"}}));
    let receipt = ChioReceipt::sign(body, &keypair).test_unwrap();
    let records = vec![EvidenceToolReceiptRecord { seq: 1, receipt }];
    let error = verify_tool_receipts(&records, None).test_unwrap_err();
    assert_eq!(error.kind(), BundleVerifyErrorKind::FeatureUnsupported);
    assert_eq!(error.exit_class(), ExitClass::VerifierContext);
}

#[test]
fn http_tool_server_receipt_without_embedded_evidence_is_refused() {
    let keypair = package_keypair();
    let mut body = sample_receipt_with_key(&keypair).body();
    body.tool_server = "http".to_string();
    let receipt = ChioReceipt::sign(body, &keypair).test_unwrap();
    let id = receipt.id.clone();
    let records = vec![EvidenceToolReceiptRecord { seq: 1, receipt }];
    let error = verify_tool_receipts(&records, None).test_unwrap_err();
    assert_eq!(
        error.message(),
        format!("HTTP receipt evidence missing: {id}")
    );
}

#[test]
fn weak_or_absent_kernel_keys_are_refused_before_any_read() {
    let mut trust = package_trust();
    trust.kernel_keys = vec![PublicKey::from_hex(
        "0100000000000000000000000000000000000000000000000000000000000000",
    )
    .test_unwrap()];
    let directory = tempfile::tempdir().test_unwrap();
    let error = verify_package(&directory.path().join("missing"), &trust, None).test_unwrap_err();
    assert!(error.message().contains("weak Ed25519"), "{error}");
    assert_eq!(error.exit_class(), ExitClass::VerifierContext);

    trust.kernel_keys = Vec::new();
    let error = verify_package(&directory.path().join("missing"), &trust, None).test_unwrap_err();
    assert_eq!(error.kind(), BundleVerifyErrorKind::TrustInvalid);
}

const DUPLICATE_KEY: &str = "urn:chio:error:attest:signed-json-invalid-input";

/// Insert a second copy of a member after the first `{` that follows `at`,
/// then recommit the manifest file entry so only the duplicate differs.
fn duplicate_nested_member(dir: &std::path::Path, file: &str, at: &str, member: &str) {
    let path = dir.join(file);
    let text = fs::read_to_string(&path).test_unwrap();
    let start = text.find(at).test_unwrap() + at.len();
    let brace = start + text[start..].find('{').test_unwrap() + 1;
    let tampered = format!("{}{member},{}", &text[..brace], &text[brace..]);
    fs::write(&path, &tampered).test_unwrap();
    if file == "manifest.json" {
        return;
    }
    let manifest_path = dir.join("manifest.json");
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).test_unwrap()).test_unwrap();
    for entry in manifest["files"].as_array_mut().test_unwrap() {
        if entry["path"] == file {
            entry["sha256"] = chio_core_types::hashing::sha256_hex(tampered.as_bytes()).into();
            entry["bytes"] = tampered.len().into();
        }
    }
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).test_unwrap(),
    )
    .test_unwrap();
}

fn assert_duplicate_refused(dir: &std::path::Path) {
    let error = verify_package(dir, &package_trust(), None).test_unwrap_err();
    assert_eq!(
        error.signed_json_source().map(|source| source.code()),
        Some(DUPLICATE_KEY),
        "{error}"
    );
    assert_eq!(error.exit_class(), ExitClass::ParseOrSchema);
}

#[test]
fn nested_duplicate_key_in_manifest_is_refused() {
    let (directory, _) = fixture();
    duplicate_nested_member(
        directory.path(),
        "manifest.json",
        "\"counts\"",
        "\"toolReceipts\": 0",
    );
    assert_duplicate_refused(directory.path());
}

#[test]
fn nested_duplicate_key_in_envelope_is_refused() {
    let (directory, _) = fixture();
    duplicate_nested_member(
        directory.path(),
        "export-envelope.json",
        "\"body\"",
        "\"schema\": \"chio.evidence_export_commitment.v1\"",
    );
    assert_duplicate_refused(directory.path());
}

#[test]
fn nested_duplicate_key_in_an_ndjson_row_is_refused() {
    let (directory, _) = fixture();
    duplicate_nested_member(
        directory.path(),
        "receipts.ndjson",
        "\"receipt\"",
        "\"id\":\"receipt-export-1\"",
    );
    assert_duplicate_refused(directory.path());
}

#[test]
fn nested_duplicate_key_in_a_json_file_is_refused() {
    let (directory, _) = fixture();
    duplicate_nested_member(
        directory.path(),
        "query.json",
        "\"readBoundary\"",
        "\"kind\": \"admin_all\"",
    );
    assert_duplicate_refused(directory.path());
}

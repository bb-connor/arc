//! Typed fixtures for package verification tests: receipts, checkpoints,
//! bundles, trust files and written packages, all at fixed times.

#![allow(dead_code)]

use std::path::Path;

use chio_bundle_verify::package::{write_package, PackageContents};
use chio_bundle_verify::verify::verify_transparency;
use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{Keypair, PublicKey};
use chio_core_types::hashing::Hash;
use chio_core_types::merkle::MerkleTree;
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::checkpoint::{CheckpointTransparencySummary, KernelCheckpoint};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::evidence::{
    EvidenceChildReceiptScope, EvidenceDisclosureNotice, EvidenceExportBundle,
    EvidenceExportCounts, EvidenceExportManifest, EvidenceExportQuery, EvidenceProofCoverage,
    EvidenceRetentionMetadata, EvidenceToolReceiptRecord, EVIDENCE_EXPORT_MANIFEST_SCHEMA,
};
use chio_core_types::receipt::kinds::TrustLevel;
use chio_core_types::root_authority::{VerifierTrust, CHIO_VERIFIER_TRUST_SCHEMA};
use chio_kernel_core::evidence_verify::{
    build_checkpoint_with_previous_at, build_evidence_transparency_claims, build_inclusion_proof,
    CheckpointError, CheckpointSigningContext, VerifiedCheckpoint,
};
use chio_security_types::clock::UnixMillis;
use chio_test_support::prelude::*;

/// Fixed issuance and export time of every fixture.
pub const ISSUED_AT: u64 = 1_792_234_800;

pub fn package_keypair() -> Keypair {
    Keypair::from_seed(&[72; 32])
}

pub fn trust_for(kernel_keys: Vec<PublicKey>) -> VerifierTrust {
    let trust = VerifierTrust {
        schema: CHIO_VERIFIER_TRUST_SCHEMA.to_string(),
        kernel_keys,
        exchange_keys: Vec::new(),
        root_policy_keys: Vec::new(),
        idp_keys: Default::default(),
        pep_keys: Default::default(),
        checkpoint_keys: Vec::new(),
        checkpoint_trust_anchor: None,
        required_columns: Vec::new(),
    };
    if let Err(error) = trust.validate() {
        panic!("fixture trust file: {error}");
    }
    trust
}

pub fn package_trust() -> VerifierTrust {
    trust_for(vec![package_keypair().public_key()])
}

pub fn sample_receipt() -> ChioReceipt {
    sample_receipt_with_key(&Keypair::generate())
}

pub fn sample_receipt_with_key(keypair: &Keypair) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "receipt-export-1".to_string(),
            timestamp: ISSUED_AT,
            capability_id: "cap-export-1".to_string(),
            tool_server: "export".to_string(),
            tool_name: "publish".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"release":"candidate-1"}))
                .test_unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-export-1".to_string(),
            policy_hash: "policy-export-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )
    .test_unwrap()
}

pub fn build_checkpoint_with_previous(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    batch: &[Vec<u8>],
    keypair: &Keypair,
    previous: Option<&VerifiedCheckpoint<'_>>,
    prior_chain: &[Hash],
) -> Result<KernelCheckpoint, CheckpointError> {
    build_checkpoint_with_previous_at(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        batch,
        CheckpointSigningContext {
            keypair,
            issued_at: UnixMillis::new(ISSUED_AT * 1000),
        },
        previous,
        prior_chain,
    )
}

pub fn build_checkpoint(
    checkpoint_seq: u64,
    batch_start_seq: u64,
    batch_end_seq: u64,
    batch: &[Vec<u8>],
    keypair: &Keypair,
) -> Result<KernelCheckpoint, CheckpointError> {
    build_checkpoint_with_previous(
        checkpoint_seq,
        batch_start_seq,
        batch_end_seq,
        batch,
        keypair,
        None,
        &[],
    )
}

/// One checkpointed receipt signed by the package key, admin-all scoped.
pub fn sample_bundle() -> EvidenceExportBundle {
    let keypair = package_keypair();
    let receipt = sample_receipt_with_key(&keypair);
    let canonical = canonical_json_bytes(&receipt).test_unwrap();
    let checkpoint =
        build_checkpoint(1, 1, 1, std::slice::from_ref(&canonical), &keypair).test_unwrap();
    let tree = MerkleTree::from_leaves(&[canonical]).test_unwrap();
    let proof = build_inclusion_proof(&tree, 0, checkpoint.body.checkpoint_seq, 1).test_unwrap();
    EvidenceExportBundle {
        query: EvidenceExportQuery::admin_all(),
        tool_receipts: vec![EvidenceToolReceiptRecord { seq: 1, receipt }],
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::FullQueryWindow,
        checkpoints: vec![checkpoint],
        capability_lineage: Vec::new(),
        inclusion_proofs: vec![proof],
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: Some(512),
            oldest_live_receipt_timestamp: Some(ISSUED_AT),
        },
    }
}

/// The manifest `write_package` would derive, without file entries.
pub fn manifest_for_bundle(bundle: &EvidenceExportBundle) -> EvidenceExportManifest {
    let count = |len: usize| u64::try_from(len).test_unwrap();
    let counts = EvidenceExportCounts {
        tool_receipts: count(bundle.tool_receipts.len()),
        child_receipts: count(bundle.child_receipts.len()),
        checkpoints: count(bundle.checkpoints.len()),
        capability_lineage: count(bundle.capability_lineage.len()),
        inclusion_proofs: count(bundle.inclusion_proofs.len()),
        uncheckpointed_receipts: count(bundle.uncheckpointed_receipts.len()),
    };
    EvidenceExportManifest {
        schema: EVIDENCE_EXPORT_MANIFEST_SCHEMA.to_string(),
        exported_at: ISSUED_AT,
        query: bundle.query.clone(),
        proof_coverage: EvidenceProofCoverage {
            checkpointed_receipts: counts
                .tool_receipts
                .saturating_sub(counts.uncheckpointed_receipts),
            uncheckpointed_receipts: counts.uncheckpointed_receipts,
        },
        receipt_semantics: chio_bundle_verify::verify::receipt_semantic_summary(
            &bundle.tool_receipts,
        ),
        counts,
        child_receipt_scope: bundle.child_receipt_scope,
        claim_boundary: None,
        files: Vec::new(),
        policy: None,
        federation_policy: None,
        disclosure_notice: EvidenceDisclosureNotice::for_query(&bundle.query),
    }
}

/// The distinct kernel keys `checkpoints` carry.
pub fn carried_keys(checkpoints: &[KernelCheckpoint]) -> Vec<PublicKey> {
    let mut keys: Vec<PublicKey> = Vec::new();
    for checkpoint in checkpoints {
        if !keys.contains(&checkpoint.body.kernel_key) {
            keys.push(checkpoint.body.kernel_key.clone());
        }
    }
    keys
}

/// Write `bundle` as a package signed by `signer`, with the transparency the
/// checkpoints derive.
pub fn write(dir: &Path, bundle: &EvidenceExportBundle, signer: &Keypair) {
    let transparency = verify_transparency(
        &bundle.checkpoints,
        None,
        &carried_keys(&bundle.checkpoints),
    )
    .test_unwrap();
    write_with_transparency(dir, bundle, &transparency, signer);
}

pub fn write_with_transparency(
    dir: &Path,
    bundle: &EvidenceExportBundle,
    transparency: &CheckpointTransparencySummary,
    signer: &Keypair,
) {
    write_package(
        dir,
        PackageContents {
            bundle,
            transparency,
            claim_boundary: build_evidence_transparency_claims(bundle, transparency, None),
            readme: "fixture package\n",
            policy: None,
            federation_policy: None,
            exported_at: ISSUED_AT,
        },
        signer,
    )
    .test_unwrap();
}

//! ARC anchoring runtime and multi-lane proof normalization.
//!
//! This crate realizes the bounded `arc-anchor` milestone over the frozen
//! checkpoint and web3 artifact family:
//!
//! - direct EVM root-registry publication requests plus confirmation helpers
//! - checkpoint-to-Bitcoin super-root aggregation and OTS linkage
//! - canonical Solana memo publication records
//! - fail-closed multi-lane proof bundle verification

#![cfg(feature = "web3")]

mod automation;
mod bitcoin;
mod bundle;
mod discovery;
mod evm;
mod functions;
mod ops;
mod solana;

use arc_core::web3::{
    validate_anchor_inclusion_proof, verify_anchor_inclusion_proof, AnchorInclusionProof,
    SignedWeb3IdentityBinding, Web3ChainAnchorRecord, Web3CheckpointStatement,
    Web3ReceiptInclusion, ARC_ANCHOR_INCLUSION_PROOF_SCHEMA, ARC_CHECKPOINT_STATEMENT_SCHEMA,
};
use arc_kernel::checkpoint::{KernelCheckpoint, KernelCheckpointBody, ReceiptInclusionProof};
use arc_kernel::evidence_export::{EvidenceExportBundle, EvidenceToolReceiptRecord};
use serde::{Deserialize, Serialize};

pub use automation::{
    assess_anchor_automation_execution, build_anchor_publication_job, AnchorAutomationExecution,
    AnchorAutomationExecutionOutcome, AnchorAutomationForwarder, AnchorAutomationJob,
    AnchorAutomationTriggerKind, ARC_ANCHOR_AUTOMATION_JOB_SCHEMA,
};
pub use bitcoin::{
    attach_bitcoin_anchor, inspect_ots_proof, prepare_ots_submission,
    verify_bitcoin_anchor_for_proof, verify_ots_proof_for_submission, BitcoinAnchorAggregation,
    ParsedOtsProof, PreparedOtsSubmission,
};
pub use bundle::{
    verify_proof_bundle, AnchorLaneKind, AnchorProofBundle, AnchorVerificationLane,
    AnchorVerificationReport, ARC_ANCHOR_PROOF_BUNDLE_SCHEMA,
};
pub use discovery::{
    build_anchor_discovery_artifact, AnchorDiscoveryArtifact, AnchorDiscoveryChain,
    AnchorDiscoveryService, AnchorDiscoveryServiceEndpoint, RootPublicationOwnership,
    ARC_ANCHOR_DISCOVERY_SCHEMA, ARC_ANCHOR_SERVICE_TYPE,
};
pub use evm::{
    build_chain_anchor_record, confirm_root_publication, ensure_publication_ready,
    inspect_publication_guard, operator_key_hash_hex, prepare_delegate_registration,
    prepare_root_publication, publish_root, verify_inclusion_onchain, EvmAnchorTarget,
    EvmPublicationGuard, EvmPublicationReceipt, PreparedDelegateRegistration,
    PreparedEvmRootPublication,
};
pub use functions::{
    assess_functions_verification, prepare_functions_batch_verification, ChainlinkFunctionsTarget,
    FunctionsBatchItem, FunctionsFallbackAssessment, FunctionsFallbackStatus,
    FunctionsVerificationPolicy, FunctionsVerificationPurpose, FunctionsVerificationResponse,
    PreparedFunctionsVerificationRequest, ARC_FUNCTIONS_ED25519_SOURCE,
};
pub use ops::{
    classify_anchor_lane, ensure_anchor_operation_allowed, AnchorAlertSeverity,
    AnchorControlChangeRecord, AnchorControlState, AnchorEmergencyControls, AnchorEmergencyMode,
    AnchorIncidentAlert, AnchorIndexerCursor, AnchorIndexerStatus, AnchorLaneHealthStatus,
    AnchorLaneRuntimeStatus, AnchorOperationKind, AnchorRuntimeReport,
    ARC_ANCHOR_RUNTIME_REPORT_SCHEMA,
};
pub use solana::{
    prepare_solana_memo_publication, verify_solana_anchor, PreparedSolanaMemoPublication,
    SolanaMemoAnchorRecord, SOLANA_MEMO_PROGRAM_ID,
};

#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("invalid anchor input: {0}")]
    InvalidInput(String),

    #[error("invalid binding: {0}")]
    InvalidBinding(String),

    #[error("rpc error: {0}")]
    Rpc(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("verification error: {0}")]
    Verification(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchorServiceConfig {
    pub evm_targets: Vec<EvmAnchorTarget>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ots_calendars: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solana_cluster: Option<String>,
}

pub fn checkpoint_statement_from_kernel(checkpoint: &KernelCheckpoint) -> Web3CheckpointStatement {
    Web3CheckpointStatement {
        schema: ARC_CHECKPOINT_STATEMENT_SCHEMA.to_string(),
        checkpoint_seq: checkpoint.body.checkpoint_seq,
        batch_start_seq: checkpoint.body.batch_start_seq,
        batch_end_seq: checkpoint.body.batch_end_seq,
        tree_size: checkpoint.body.tree_size as u64,
        merkle_root: checkpoint.body.merkle_root,
        issued_at: checkpoint.body.issued_at,
        kernel_key: checkpoint.body.kernel_key.clone(),
        signature: checkpoint.signature.clone(),
    }
}

pub fn kernel_checkpoint_from_statement(statement: &Web3CheckpointStatement) -> KernelCheckpoint {
    KernelCheckpoint {
        body: KernelCheckpointBody {
            schema: statement.schema.clone(),
            checkpoint_seq: statement.checkpoint_seq,
            batch_start_seq: statement.batch_start_seq,
            batch_end_seq: statement.batch_end_seq,
            tree_size: statement.tree_size as usize,
            merkle_root: statement.merkle_root,
            issued_at: statement.issued_at,
            kernel_key: statement.kernel_key.clone(),
        },
        signature: statement.signature.clone(),
    }
}

pub fn receipt_inclusion_from_kernel(proof: &ReceiptInclusionProof) -> Web3ReceiptInclusion {
    Web3ReceiptInclusion {
        checkpoint_seq: proof.checkpoint_seq,
        merkle_root: proof.merkle_root,
        proof: proof.proof.clone(),
    }
}

pub fn build_anchor_inclusion_proof(
    receipt: arc_core::receipt::ArcReceipt,
    inclusion: &ReceiptInclusionProof,
    checkpoint: &KernelCheckpoint,
    chain_anchor: Option<Web3ChainAnchorRecord>,
    binding: SignedWeb3IdentityBinding,
) -> Result<AnchorInclusionProof, AnchorError> {
    let proof = AnchorInclusionProof {
        schema: ARC_ANCHOR_INCLUSION_PROOF_SCHEMA.to_string(),
        receipt,
        receipt_inclusion: receipt_inclusion_from_kernel(inclusion),
        checkpoint_statement: checkpoint_statement_from_kernel(checkpoint),
        chain_anchor,
        bitcoin_anchor: None,
        super_root_inclusion: None,
        key_binding_certificate: binding,
    };
    validate_anchor_inclusion_proof(&proof)
        .map_err(|error| AnchorError::Verification(error.to_string()))?;
    verify_anchor_inclusion_proof(&proof)
        .map_err(|error| AnchorError::Verification(error.to_string()))?;
    Ok(proof)
}

pub fn build_anchor_inclusion_proof_from_evidence_bundle(
    bundle: &EvidenceExportBundle,
    receipt_id: &str,
    chain_anchor: Option<Web3ChainAnchorRecord>,
    binding: SignedWeb3IdentityBinding,
) -> Result<AnchorInclusionProof, AnchorError> {
    if bundle
        .uncheckpointed_receipts
        .iter()
        .any(|receipt| receipt.receipt_id == receipt_id)
    {
        return Err(AnchorError::Verification(format!(
            "receipt `{receipt_id}` is not checkpointed in the canonical evidence bundle"
        )));
    }

    let record = exactly_one_tool_receipt(bundle, receipt_id)?;
    let inclusion = exactly_one_inclusion_proof(bundle, record.seq, receipt_id)?;
    let checkpoint = exactly_one_checkpoint(bundle, inclusion.checkpoint_seq, receipt_id)?;

    build_anchor_inclusion_proof(
        record.receipt.clone(),
        inclusion,
        checkpoint,
        chain_anchor,
        binding,
    )
}

fn exactly_one_tool_receipt<'a>(
    bundle: &'a EvidenceExportBundle,
    receipt_id: &str,
) -> Result<&'a EvidenceToolReceiptRecord, AnchorError> {
    let mut matches = bundle
        .tool_receipts
        .iter()
        .filter(|record| record.receipt.id == receipt_id);
    let Some(record) = matches.next() else {
        return Err(AnchorError::Verification(format!(
            "receipt `{receipt_id}` is missing from the canonical evidence bundle"
        )));
    };
    if matches.next().is_some() {
        return Err(AnchorError::Verification(format!(
            "receipt `{receipt_id}` appears multiple times in the canonical evidence bundle"
        )));
    }
    Ok(record)
}

fn exactly_one_inclusion_proof<'a>(
    bundle: &'a EvidenceExportBundle,
    receipt_seq: u64,
    receipt_id: &str,
) -> Result<&'a ReceiptInclusionProof, AnchorError> {
    let mut matches = bundle
        .inclusion_proofs
        .iter()
        .filter(|proof| proof.receipt_seq == receipt_seq);
    let Some(inclusion) = matches.next() else {
        return Err(AnchorError::Verification(format!(
            "receipt `{receipt_id}` is missing an inclusion proof in the canonical evidence bundle"
        )));
    };
    if matches.next().is_some() {
        return Err(AnchorError::Verification(format!(
            "receipt `{receipt_id}` has multiple inclusion proofs in the canonical evidence bundle"
        )));
    }
    Ok(inclusion)
}

fn exactly_one_checkpoint<'a>(
    bundle: &'a EvidenceExportBundle,
    checkpoint_seq: u64,
    receipt_id: &str,
) -> Result<&'a KernelCheckpoint, AnchorError> {
    let mut matches = bundle
        .checkpoints
        .iter()
        .filter(|checkpoint| checkpoint.body.checkpoint_seq == checkpoint_seq);
    let Some(checkpoint) = matches.next() else {
        return Err(AnchorError::Verification(format!(
            "receipt `{receipt_id}` is missing checkpoint `{checkpoint_seq}` in the canonical evidence bundle"
        )));
    };
    if matches.next().is_some() {
        return Err(AnchorError::Verification(format!(
            "receipt `{receipt_id}` has multiple checkpoint records for `{checkpoint_seq}` in the canonical evidence bundle"
        )));
    }
    Ok(checkpoint)
}

#[cfg(test)]
mod tests {
    use arc_core::web3::AnchorInclusionProof;
    use arc_kernel::evidence_export::{
        EvidenceChildReceiptScope, EvidenceExportBundle, EvidenceExportQuery,
        EvidenceRetentionMetadata, EvidenceToolReceiptRecord, EvidenceUncheckpointedReceipt,
    };
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;
    use opentimestamps::attestation::Attestation;
    use opentimestamps::ser::{DetachedTimestampFile, DigestType};
    use opentimestamps::timestamp::{Step, StepData, Timestamp};

    use super::{
        attach_bitcoin_anchor, build_anchor_discovery_artifact, build_anchor_inclusion_proof,
        build_anchor_inclusion_proof_from_evidence_bundle, inspect_ots_proof,
        kernel_checkpoint_from_statement, prepare_ots_submission, prepare_root_publication,
        prepare_solana_memo_publication, verify_bitcoin_anchor_for_proof,
        verify_ots_proof_for_submission, verify_proof_bundle, AnchorLaneKind, AnchorProofBundle,
        AnchorServiceConfig, EvmAnchorTarget, SolanaMemoAnchorRecord,
    };

    fn sample_primary_proof() -> AnchorInclusionProof {
        serde_json::from_str(include_str!(
            "../../../docs/standards/ARC_ANCHOR_INCLUSION_PROOF_EXAMPLE.json"
        ))
        .unwrap()
    }

    fn synthetic_ots_proof(start_digest: &[u8; 32], bitcoin_height: u64) -> String {
        let ots = DetachedTimestampFile {
            digest_type: DigestType::Sha256,
            timestamp: Timestamp {
                start_digest: start_digest.to_vec(),
                first_step: Step {
                    data: StepData::Attestation(Attestation::Bitcoin {
                        height: bitcoin_height as usize,
                    }),
                    output: start_digest.to_vec(),
                    next: Vec::new(),
                },
            },
        };
        let mut bytes = Vec::new();
        ots.to_writer(&mut bytes).unwrap();
        BASE64_STANDARD.encode(bytes)
    }

    fn sample_evidence_bundle() -> EvidenceExportBundle {
        let proof = sample_primary_proof();
        let checkpoint = kernel_checkpoint_from_statement(&proof.checkpoint_statement);
        let inclusion = arc_kernel::checkpoint::ReceiptInclusionProof {
            checkpoint_seq: proof.receipt_inclusion.checkpoint_seq,
            receipt_seq: proof.checkpoint_statement.batch_start_seq,
            leaf_index: proof.receipt_inclusion.proof.leaf_index,
            merkle_root: proof.receipt_inclusion.merkle_root.clone(),
            proof: proof.receipt_inclusion.proof.clone(),
        };

        EvidenceExportBundle {
            query: EvidenceExportQuery::default(),
            tool_receipts: vec![EvidenceToolReceiptRecord {
                seq: inclusion.receipt_seq,
                receipt: proof.receipt.clone(),
            }],
            child_receipts: vec![],
            child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
            checkpoints: vec![checkpoint],
            capability_lineage: vec![],
            inclusion_proofs: vec![inclusion],
            uncheckpointed_receipts: vec![],
            retention: EvidenceRetentionMetadata {
                live_db_size_bytes: 0,
                oldest_live_receipt_timestamp: None,
            },
        }
    }

    #[test]
    fn root_publication_request_matches_primary_example() {
        let proof = sample_primary_proof();
        let checkpoint = kernel_checkpoint_from_statement(&proof.checkpoint_statement);
        let request = prepare_root_publication(
            &EvmAnchorTarget {
                chain_id: "eip155:8453".to_string(),
                rpc_url: "http://127.0.0.1:8545".to_string(),
                contract_address: "0x1000000000000000000000000000000000000001".to_string(),
                operator_address: proof
                    .key_binding_certificate
                    .certificate
                    .settlement_address
                    .clone(),
                publisher_address: proof
                    .key_binding_certificate
                    .certificate
                    .settlement_address
                    .clone(),
            },
            &checkpoint,
            &proof.key_binding_certificate,
        )
        .unwrap();

        assert_eq!(
            request.checkpoint_seq,
            proof.checkpoint_statement.checkpoint_seq
        );
        assert_eq!(request.merkle_root, proof.checkpoint_statement.merkle_root);
        assert!(request.call_data.starts_with("0x"));
    }

    #[test]
    fn bitcoin_attachment_builds_super_root_linkage() {
        let proof = sample_primary_proof();
        let checkpoint = kernel_checkpoint_from_statement(&proof.checkpoint_statement);
        let submission = prepare_ots_submission(
            std::slice::from_ref(&checkpoint),
            &[String::from(
                "https://alice.btc.calendar.opentimestamps.org",
            )],
        )
        .unwrap();
        let ots_proof = synthetic_ots_proof(submission.document_digest.as_bytes(), 900_000);

        let upgraded = attach_bitcoin_anchor(
            &proof,
            &submission,
            900_000,
            "0000000000000000000abc".to_string(),
            ots_proof,
        )
        .unwrap();

        assert!(upgraded.bitcoin_anchor.is_some());
        assert!(upgraded.super_root_inclusion.is_some());
    }

    #[test]
    fn ots_proof_inspection_tracks_digest_and_attestation() {
        let proof = sample_primary_proof();
        let checkpoint = kernel_checkpoint_from_statement(&proof.checkpoint_statement);
        let submission = prepare_ots_submission(
            std::slice::from_ref(&checkpoint),
            &[String::from(
                "https://alice.btc.calendar.opentimestamps.org",
            )],
        )
        .unwrap();
        let ots_proof = synthetic_ots_proof(submission.document_digest.as_bytes(), 900_000);

        let inspection = inspect_ots_proof(&ots_proof).unwrap();
        assert_eq!(inspection.digest_algorithm, "sha256");
        assert_eq!(
            inspection.start_digest,
            submission.document_digest.to_hex_prefixed()
        );
        assert_eq!(inspection.bitcoin_attestation_heights, vec![900_000]);

        let verified =
            verify_ots_proof_for_submission(&submission, &ots_proof, Some(900_000)).unwrap();
        assert_eq!(verified.bitcoin_attestation_heights, vec![900_000]);
    }

    #[test]
    fn bitcoin_bundle_verifies_ots_commitment_against_super_root() {
        let proof = sample_primary_proof();
        let checkpoint = kernel_checkpoint_from_statement(&proof.checkpoint_statement);
        let submission = prepare_ots_submission(
            std::slice::from_ref(&checkpoint),
            &[String::from(
                "https://alice.btc.calendar.opentimestamps.org",
            )],
        )
        .unwrap();
        let ots_proof = synthetic_ots_proof(submission.document_digest.as_bytes(), 900_000);
        let upgraded = attach_bitcoin_anchor(
            &proof,
            &submission,
            900_000,
            "0000000000000000000abc".to_string(),
            ots_proof,
        )
        .unwrap();

        let inspection = verify_bitcoin_anchor_for_proof(&upgraded).unwrap();
        assert_eq!(
            inspection.start_digest,
            submission.document_digest.to_hex_prefixed()
        );

        let bundle = AnchorProofBundle {
            schema: super::ARC_ANCHOR_PROOF_BUNDLE_SCHEMA.to_string(),
            primary_proof: upgraded,
            secondary_lanes: vec![AnchorLaneKind::BitcoinOts],
            solana_anchor: None,
            note: None,
        };

        let report = verify_proof_bundle(&bundle).unwrap();
        assert!(report.verified);
        assert!(report
            .lanes
            .iter()
            .any(|lane| lane.lane == AnchorLaneKind::BitcoinOts && lane.verified));
    }

    #[test]
    fn bitcoin_bundle_rejects_wrong_super_root_digest() {
        let proof = sample_primary_proof();
        let checkpoint = kernel_checkpoint_from_statement(&proof.checkpoint_statement);
        let submission = prepare_ots_submission(
            std::slice::from_ref(&checkpoint),
            &[String::from(
                "https://alice.btc.calendar.opentimestamps.org",
            )],
        )
        .unwrap();
        let ots_proof = synthetic_ots_proof(submission.document_digest.as_bytes(), 900_000);
        let mut upgraded = attach_bitcoin_anchor(
            &proof,
            &submission,
            900_000,
            "0000000000000000000abc".to_string(),
            ots_proof,
        )
        .unwrap();
        upgraded.super_root_inclusion.as_mut().unwrap().super_root =
            arc_core::hashing::sha256(b"wrong-super-root");

        let error = verify_bitcoin_anchor_for_proof(&upgraded).unwrap_err();
        assert!(error
            .to_string()
            .contains("does not commit to the expected ARC super-root digest"));
    }

    #[test]
    fn solana_bundle_verifies_when_root_matches() {
        let proof = sample_primary_proof();
        let checkpoint = kernel_checkpoint_from_statement(&proof.checkpoint_statement);
        let prepared = prepare_solana_memo_publication(
            &checkpoint,
            "solana:mainnet-beta",
            "7xKXtg2CW9Q4hN7kD6A6tVWyQGm9Xxq6u9rY2T6yQkZp",
        )
        .unwrap();

        let bundle = AnchorProofBundle {
            schema: super::ARC_ANCHOR_PROOF_BUNDLE_SCHEMA.to_string(),
            primary_proof: proof,
            secondary_lanes: vec![AnchorLaneKind::SolanaMemo],
            solana_anchor: Some(SolanaMemoAnchorRecord::from_prepared(
                &prepared,
                "5W8D7gF9w3mP2nL6e1c4k7T9y2V6a1b3s5d7f9g2h4j6k8m1n3p5q7r9t1u3v5w7".to_string(),
                310_045_221,
                1_743_600_000,
            )),
            note: None,
        };

        let report = verify_proof_bundle(&bundle).unwrap();
        assert!(report.verified);
        assert!(report
            .lanes
            .iter()
            .any(|lane| lane.lane == AnchorLaneKind::SolanaMemo && lane.verified));
    }

    #[test]
    fn solana_bundle_rejects_mismatched_roots() {
        let proof = sample_primary_proof();
        let checkpoint = kernel_checkpoint_from_statement(&proof.checkpoint_statement);
        let prepared = prepare_solana_memo_publication(
            &checkpoint,
            "solana:mainnet-beta",
            "7xKXtg2CW9Q4hN7kD6A6tVWyQGm9Xxq6u9rY2T6yQkZp",
        )
        .unwrap();
        let mut solana = SolanaMemoAnchorRecord::from_prepared(
            &prepared,
            "5W8D7gF9w3mP2nL6e1c4k7T9y2V6a1b3s5d7f9g2h4j6k8m1n3p5q7r9t1u3v5w7".to_string(),
            310_045_221,
            1_743_600_000,
        );
        solana.anchored_checkpoint_seq += 1;

        let bundle = AnchorProofBundle {
            schema: super::ARC_ANCHOR_PROOF_BUNDLE_SCHEMA.to_string(),
            primary_proof: proof,
            secondary_lanes: vec![AnchorLaneKind::SolanaMemo],
            solana_anchor: Some(solana),
            note: None,
        };

        let error = verify_proof_bundle(&bundle).unwrap_err();
        assert!(error.to_string().contains("Solana anchor"));
    }

    #[test]
    fn example_proof_projects_back_into_anchor_inclusion() {
        let proof = sample_primary_proof();
        let checkpoint = kernel_checkpoint_from_statement(&proof.checkpoint_statement);
        let inclusion = arc_kernel::checkpoint::ReceiptInclusionProof {
            checkpoint_seq: proof.receipt_inclusion.checkpoint_seq,
            receipt_seq: proof.checkpoint_statement.batch_start_seq,
            leaf_index: proof.receipt_inclusion.proof.leaf_index,
            merkle_root: proof.receipt_inclusion.merkle_root,
            proof: proof.receipt_inclusion.proof.clone(),
        };
        let projected = build_anchor_inclusion_proof(
            proof.receipt.clone(),
            &inclusion,
            &checkpoint,
            proof.chain_anchor.clone(),
            proof.key_binding_certificate.clone(),
        )
        .unwrap();
        assert_eq!(projected.checkpoint_statement.checkpoint_seq, 1_042);
    }

    #[test]
    fn evidence_bundle_projects_back_into_anchor_inclusion() {
        let proof = sample_primary_proof();
        let bundle = sample_evidence_bundle();

        let projected = build_anchor_inclusion_proof_from_evidence_bundle(
            &bundle,
            &proof.receipt.id,
            proof.chain_anchor.clone(),
            proof.key_binding_certificate.clone(),
        )
        .unwrap();

        assert_eq!(projected.receipt.id, proof.receipt.id);
        assert_eq!(projected.checkpoint_statement.checkpoint_seq, 1_042);
    }

    #[test]
    fn evidence_bundle_rejects_uncheckpointed_receipts() {
        let proof = sample_primary_proof();
        let mut bundle = sample_evidence_bundle();
        bundle
            .uncheckpointed_receipts
            .push(EvidenceUncheckpointedReceipt {
                seq: proof.checkpoint_statement.batch_start_seq,
                receipt_id: proof.receipt.id.clone(),
            });

        let error = build_anchor_inclusion_proof_from_evidence_bundle(
            &bundle,
            &proof.receipt.id,
            proof.chain_anchor.clone(),
            proof.key_binding_certificate.clone(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("not checkpointed"));
    }

    #[test]
    fn evidence_bundle_rejects_missing_checkpoint_records() {
        let proof = sample_primary_proof();
        let mut bundle = sample_evidence_bundle();
        bundle.checkpoints.clear();

        let error = build_anchor_inclusion_proof_from_evidence_bundle(
            &bundle,
            &proof.receipt.id,
            proof.chain_anchor.clone(),
            proof.key_binding_certificate.clone(),
        )
        .unwrap_err();

        assert!(error.to_string().contains("missing checkpoint"));
    }

    #[test]
    fn discovery_artifact_projects_binding_and_service_inventory() {
        let proof = sample_primary_proof();
        let discovery = build_anchor_discovery_artifact(
            &AnchorServiceConfig {
                evm_targets: vec![
                    EvmAnchorTarget {
                        chain_id: "eip155:8453".to_string(),
                        rpc_url: "http://127.0.0.1:8545".to_string(),
                        contract_address: "0x1000000000000000000000000000000000000001".to_string(),
                        operator_address: "0x1111111111111111111111111111111111111111".to_string(),
                        publisher_address: "0x1111111111111111111111111111111111111111".to_string(),
                    },
                    EvmAnchorTarget {
                        chain_id: "eip155:42161".to_string(),
                        rpc_url: "http://127.0.0.1:8546".to_string(),
                        contract_address: "0x2000000000000000000000000000000000000001".to_string(),
                        operator_address: "0x1111111111111111111111111111111111111111".to_string(),
                        publisher_address: "0x2222222222222222222222222222222222222222".to_string(),
                    },
                ],
                ots_calendars: vec![String::from(
                    "https://alice.btc.calendar.opentimestamps.org",
                )],
                solana_cluster: Some("solana:mainnet-beta".to_string()),
            },
            &proof.key_binding_certificate,
        )
        .unwrap();

        assert_eq!(
            discovery.arc_identity,
            proof.key_binding_certificate.certificate.arc_identity
        );
        assert_eq!(discovery.service.service_type, "ArcAnchorService");
        assert_eq!(discovery.service.service_endpoint.chains.len(), 2);
        assert_eq!(
            discovery
                .service
                .service_endpoint
                .bitcoin_anchor_method
                .as_deref(),
            Some("opentimestamps")
        );
        assert!(discovery.root_publication_ownership[1].delegate_publication_allowed);
    }
}

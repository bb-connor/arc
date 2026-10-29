use super::*;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use chio_core::crypto::Keypair;
use chio_core::receipt::crypto_floor::ReceiptCryptoFloor;
use chio_core::receipt::evidence::{EvidenceRetentionMetadata, EvidenceToolReceiptRecord};
use chio_core::receipt::{
    body::ChioReceipt, body::ChioReceiptBody, decision::Decision, decision::ToolCallAction,
};
use chio_core_types::root_authority::{VerifierTrust, CHIO_VERIFIER_TRUST_SCHEMA};
use chio_kernel::build_checkpoint;

use chio_test_support::prelude::*;

#[path = "tests/http_receipts.rs"]
mod http_receipts;

#[path = "tests/hello_receipt_fixture.rs"]
mod hello_receipt_fixture;

const PACKAGE_EXPORTED_AT: u64 = 1_775_137_700;

fn carried_kernel_keys(checkpoints: &[chio_kernel::KernelCheckpoint]) -> Vec<chio_core::PublicKey> {
    let mut keys: Vec<chio_core::PublicKey> = Vec::new();
    for checkpoint in checkpoints {
        if !keys.contains(&checkpoint.body.kernel_key) {
            keys.push(checkpoint.body.kernel_key.clone());
        }
    }
    keys
}

fn assert_registry_error(err: &CliError, expected_code: &str, expected_domain: &str) {
    match err {
        CliError::Chio(chio) => {
            assert_eq!(chio.code().as_str(), expected_code);
            assert_eq!(chio.domain().as_str(), expected_domain);
        }
        other => panic!("expected registry-backed CliError::Chio, got: {other:?}"),
    }
}

fn unique_test_dir(name: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .test_unwrap()
        .as_nanos();
    std::env::temp_dir().join(format!(
        "chio-evidence-{name}-{}-{stamp}",
        std::process::id()
    ))
}

#[test]
fn output_path_file_uses_cli_domain() {
    let temp = unique_test_dir("file-output");
    std::fs::create_dir_all(&temp).test_unwrap();
    let output = temp.join("evidence-output");
    std::fs::write(&output, b"not a directory").test_unwrap();

    let error = ensure_clean_output_dir(&output).test_unwrap_err();

    assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
    let _ = std::fs::remove_dir_all(&temp);
}

#[test]
fn output_path_nonempty_directory_uses_cli_domain() {
    let temp = unique_test_dir("nonempty-output");
    std::fs::create_dir_all(&temp).test_unwrap();
    let output = temp.join("evidence-output");
    std::fs::create_dir_all(&output).test_unwrap();
    std::fs::write(output.join("existing.json"), b"{}").test_unwrap();

    let error = ensure_clean_output_dir(&output).test_unwrap_err();

    assert_registry_error(&error, "urn:chio:error:cli:other", "cli");
    let _ = std::fs::remove_dir_all(&temp);
}

fn sample_receipt_with_key(keypair: &Keypair) -> ChioReceipt {
    ChioReceipt::sign(
        ChioReceiptBody {
            id: "receipt-export-1".to_string(),
            timestamp: 1_775_137_626,
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
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )
    .test_unwrap()
}
fn package_keypair() -> Keypair {
    Keypair::from_seed(&[72; 32])
}

fn kernel_trust(kernel_keys: Vec<chio_core::crypto::PublicKey>) -> VerifierTrust {
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
    trust.validate().test_unwrap();
    trust
}

fn package_trust() -> VerifierTrust {
    kernel_trust(vec![package_keypair().public_key()])
}

fn sample_bundle() -> EvidenceExportBundle {
    let checkpoint_keypair = package_keypair();
    let receipt = sample_receipt_with_key(&checkpoint_keypair);
    let canonical = canonical_json_bytes(&receipt).test_unwrap();
    let checkpoint = build_checkpoint(
        1,
        1,
        1,
        std::slice::from_ref(&canonical),
        &checkpoint_keypair,
    )
    .test_unwrap();
    let tree = chio_core::merkle::MerkleTree::from_leaves(&[canonical]).test_unwrap();
    let proof = chio_kernel_core::evidence_verify::build_inclusion_proof(
        &tree,
        0,
        checkpoint.body.checkpoint_seq,
        1,
    )
    .test_unwrap();
    EvidenceExportBundle {
        query: EvidenceExportQuery::default(),
        tool_receipts: vec![EvidenceToolReceiptRecord { seq: 1, receipt }],
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::OmittedNoJoinPath,
        checkpoints: vec![checkpoint],
        capability_lineage: Vec::new(),
        inclusion_proofs: vec![proof],
        uncheckpointed_receipts: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: Some(512),
            oldest_live_receipt_timestamp: Some(1_775_137_626),
        },
    }
}

#[test]
fn merge_export_query_preserves_policy_tenant_scope() {
    let merged = merge_export_query(
        &EvidenceExportQuery {
            capability_id: Some("cap-1".to_string()),
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
        },
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: Some("agent-1".to_string()),
            since: None,
            until: None,
            tenant: None,
            read_boundary: None,
        },
    )
    .test_unwrap();

    assert_eq!(merged.capability_id.as_deref(), Some("cap-1"));
    assert_eq!(merged.agent_subject.as_deref(), Some("agent-1"));
    assert_eq!(merged.tenant.as_deref(), Some("tenant-a"));
}

#[test]
fn merge_export_query_rejects_tenant_scope_expansion() {
    let error = merge_export_query(
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-a")),
        },
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-b".to_string()),
            read_boundary: Some(ReceiptReadBoundary::tenant_scoped("tenant-b")),
        },
    )
    .test_unwrap_err();

    assert!(error.to_string().contains("tenant"));
}

#[test]
fn merge_export_query_allows_admin_policy_to_narrow_to_tenant_filter() {
    let merged = merge_export_query(
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: None,
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
        },
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: Some("tenant-a".to_string()),
            read_boundary: None,
        },
    )
    .test_unwrap();

    assert_eq!(merged.tenant.as_deref(), Some("tenant-a"));
    assert_eq!(merged.read_boundary, Some(ReceiptReadBoundary::AdminAll));
}

#[test]
fn merge_export_query_rejects_request_chosen_boundary_without_policy_binding() {
    let error = merge_export_query(
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: None,
            read_boundary: None,
        },
        &EvidenceExportQuery {
            capability_id: None,
            agent_subject: None,
            since: None,
            until: None,
            tenant: None,
            read_boundary: Some(ReceiptReadBoundary::AdminAll),
        },
    )
    .test_unwrap_err();

    assert!(
        error.to_string().contains("read boundary"),
        "unexpected error: {error}"
    );
}

//! Deterministic generator for `examples/hello-receipt-verify/fixtures/minimal-evidence`.
//!
//! Set `CHIO_WRITE_HELLO_RECEIPT_FIXTURES=1` to rewrite the committed package
//! from this generator. Without it the test requires the committed directory
//! to hold exactly the generated file set, byte for byte.

use std::collections::BTreeMap;

use super::*;
use chio_core::capability::scope::{ChioScope, Operation, ToolGrant};
use chio_core::capability::token::{CapabilityToken, CapabilityTokenBody};
use chio_core::receipt::evidence::{
    CapabilitySnapshot, CapabilitySnapshotProvenance, EvidenceUncheckpointedReceipt,
};

const EXAMPLE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples/hello-receipt-verify"
);
const FIXTURE_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../../examples/hello-receipt-verify/fixtures/minimal-evidence"
);
const WRITE_ENV: &str = "CHIO_WRITE_HELLO_RECEIPT_FIXTURES";

/// The committed example kernel seed; `verifier-trust.json` pins its key.
const KERNEL_SEED_HEX: &str =
    include_str!("../../../../../../examples/hello-receipt-verify/fixtures/kernel.seed");
const AGENT_SEED: [u8; 32] = [0x22; 32];

const CAPABILITY_ID: &str = "cap-hello-receipt-verify-1";
const ISSUED_AT: u64 = 1_775_000_000;
const EXPIRES_AT: u64 = ISSUED_AT + 3_600;
const RECEIPT_AT: u64 = ISSUED_AT + 15;
const EXPORTED_AT: u64 = ISSUED_AT + 60;

fn kernel_keypair() -> Keypair {
    Keypair::from_seed_hex(KERNEL_SEED_HEX.trim()).test_unwrap()
}

fn hello_bundle() -> EvidenceExportBundle {
    let kernel = kernel_keypair();
    let agent = Keypair::from_seed(&AGENT_SEED);
    let capability = CapabilityToken::sign(
        CapabilityTokenBody {
            id: CAPABILITY_ID.to_string(),
            issuer: kernel.public_key(),
            subject: agent.public_key(),
            scope: ChioScope {
                grants: vec![ToolGrant {
                    server_id: "*".to_string(),
                    tool_name: "*".to_string(),
                    operations: vec![Operation::Invoke],
                    constraints: Vec::new(),
                    max_invocations: None,
                    max_cost_per_invocation: None,
                    max_total_cost: None,
                    dpop_required: None,
                }],
                ..ChioScope::default()
            },
            issued_at: ISSUED_AT,
            expires_at: EXPIRES_AT,
            delegation_chain: Vec::new(),
            aggregate_invocation_budget: None,
        },
        &kernel,
    )
    .test_unwrap();
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: "hello-receipt-verify-1".to_string(),
            timestamp: RECEIPT_AT,
            capability_id: CAPABILITY_ID.to_string(),
            tool_server: "*".to_string(),
            tool_name: "read_file".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({"path": "README.md"}))
                .test_unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(b"hello-receipt-verify content"),
            policy_hash: sha256_hex(b"hello-receipt-verify policy"),
            evidence: Vec::new(),
            metadata: Some(serde_json::json!({
                "attribution": {
                    "subject_key": agent.public_key().to_hex(),
                    "issuer_key": kernel.public_key().to_hex(),
                    "delegation_depth": 0,
                    "grant_index": 0,
                }
            })),
            trust_level: Default::default(),
            tenant_id: None,
            kernel_key: kernel.public_key(),
            bbs_projection_version: None,
        },
        &kernel,
    )
    .test_unwrap();
    let lineage = CapabilitySnapshot {
        capability_id: capability.id.clone(),
        subject_key: capability.subject.to_hex(),
        issuer_key: capability.issuer.to_hex(),
        issued_at: capability.issued_at,
        expires_at: capability.expires_at,
        grants_json: serde_json::to_string(&capability.scope).test_unwrap(),
        delegation_depth: 0,
        parent_capability_id: None,
        federated_parent_capability_id: None,
        provenance: CapabilitySnapshotProvenance::SignedToken,
        signed_capability: Some(capability),
    };
    EvidenceExportBundle {
        query: EvidenceExportQuery::admin_all(),
        uncheckpointed_receipts: vec![EvidenceUncheckpointedReceipt {
            seq: 1,
            receipt_id: receipt.id.clone(),
        }],
        tool_receipts: vec![EvidenceToolReceiptRecord { seq: 1, receipt }],
        child_receipts: Vec::new(),
        child_receipt_scope: EvidenceChildReceiptScope::FullQueryWindow,
        checkpoints: Vec::new(),
        capability_lineage: vec![lineage],
        inclusion_proofs: Vec::new(),
        retention: EvidenceRetentionMetadata {
            live_db_size_bytes: Some(4_096),
            oldest_live_receipt_timestamp: Some(RECEIPT_AT),
        },
    }
}

fn package_files(root: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, dir: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
        for entry in fs::read_dir(dir).test_unwrap() {
            let path = entry.test_unwrap().path();
            if path.is_dir() {
                walk(root, &path, files);
            } else {
                let name = path
                    .strip_prefix(root)
                    .test_unwrap()
                    .to_string_lossy()
                    .into_owned();
                files.insert(name, fs::read(&path).test_unwrap());
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(root, root, &mut files);
    files
}

#[test]
fn committed_hello_receipt_fixture_is_the_generator_output() {
    let scratch = chio_test_support::private_tempdir().test_unwrap();
    let generated_dir = scratch.path().join("minimal-evidence");
    write_evidence_package(
        &generated_dir,
        hello_bundle(),
        None,
        None,
        None,
        &kernel_keypair(),
        EXPORTED_AT,
    )
    .test_unwrap();
    let generated = package_files(&generated_dir);

    let committed_dir = Path::new(FIXTURE_DIR);
    if std::env::var_os(WRITE_ENV).is_some() {
        if committed_dir.exists() {
            fs::remove_dir_all(committed_dir).test_unwrap();
        }
        fs::create_dir_all(committed_dir).test_unwrap();
        for (name, bytes) in &generated {
            fs::write(committed_dir.join(name), bytes).test_unwrap();
        }
    }

    let committed = package_files(committed_dir);
    assert_eq!(
        committed.keys().collect::<Vec<_>>(),
        generated.keys().collect::<Vec<_>>(),
        "committed file set drifted; rerun with {WRITE_ENV}=1"
    );
    for (name, bytes) in &generated {
        assert!(
            committed.get(name) == Some(bytes),
            "{name} drifted; rerun with {WRITE_ENV}=1"
        );
    }

    let trust = chio_bundle_verify::trust::read_trust_file(
        &Path::new(EXAMPLE_DIR).join("verifier-trust.json"),
    )
    .test_unwrap();
    assert_eq!(trust.kernel_keys, vec![kernel_keypair().public_key()]);
    let verified =
        chio_bundle_verify::verify::verify_package(committed_dir, &trust, None).test_unwrap();
    assert_eq!(verified.package.manifest.counts.tool_receipts, 1);
    assert_eq!(verified.package.manifest.counts.uncheckpointed_receipts, 1);
}

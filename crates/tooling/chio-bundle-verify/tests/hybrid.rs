//! Packages carry no policy crypto floor: classical and hybrid receipt
//! signatures both verify, and a hybrid decision still counts as authorized.
#![cfg(feature = "pq")]

use chio_bundle_verify::verify::{
    receipt_semantic_summary, verify_child_receipts, verify_tool_receipts,
};
use chio_core_types::crypto::{
    Ed25519Backend, HybridBackend, Keypair, MlDsa65Backend, SigningBackend,
};
use chio_core_types::receipt::body::{ChioReceipt, ChioReceiptBody};
use chio_core_types::receipt::decision::{Decision, ToolCallAction};
use chio_core_types::receipt::evidence::{EvidenceChildReceiptRecord, EvidenceToolReceiptRecord};
use chio_core_types::receipt::kinds::TrustLevel;
use chio_core_types::receipt::lineage::{ChildRequestReceipt, ChildRequestReceiptBody};
use chio_core_types::session::{OperationKind, OperationTerminalState, RequestId, SessionId};
use chio_test_support::prelude::*;

fn hybrid_backend(seed: [u8; 32]) -> HybridBackend {
    let pq = MlDsa65Backend::from_seed(&seed);
    HybridBackend::new(Box::new(Ed25519Backend::new(Keypair::generate())), pq).test_unwrap()
}

#[test]
fn hybrid_receipts_verify_without_a_policy_floor() {
    let backend = hybrid_backend([9u8; 32]);
    let receipt = ChioReceipt::sign_with_backend(
        ChioReceiptBody {
            id: "receipt-export-hybrid-1".to_string(),
            timestamp: 1_792_234_800,
            capability_id: "cap-export-hybrid-1".to_string(),
            tool_server: "export".to_string(),
            tool_name: "publish".to_string(),
            action: ToolCallAction::from_parameters(
                serde_json::json!({"release":"candidate-hybrid"}),
            )
            .test_unwrap(),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-export-hybrid-1".to_string(),
            policy_hash: "policy-export-hybrid-1".to_string(),
            evidence: Vec::new(),
            metadata: None,
            trust_level: TrustLevel::default(),
            tenant_id: None,
            kernel_key: backend.public_key().test_unwrap(),
            bbs_projection_version: None,
        },
        &backend,
    )
    .test_unwrap();
    let child_backend = hybrid_backend([10u8; 32]);
    let child = ChildRequestReceipt::sign_with_backend(
        ChildRequestReceiptBody {
            id: "child-receipt-export-hybrid-1".to_string(),
            timestamp: 1_792_234_801,
            session_id: SessionId::new("sess-export-hybrid-1"),
            parent_request_id: RequestId::new("parent-export-hybrid-1"),
            request_id: RequestId::new("child-export-hybrid-1"),
            operation_kind: OperationKind::CreateMessage,
            terminal_state: OperationTerminalState::Completed,
            outcome_hash: "outcome-export-hybrid-1".to_string(),
            policy_hash: "policy-export-hybrid-1".to_string(),
            metadata: None,
            kernel_key: child_backend.public_key().test_unwrap(),
        },
        &child_backend,
    )
    .test_unwrap();
    let tool_receipts = vec![EvidenceToolReceiptRecord { seq: 1, receipt }];
    let verified = verify_tool_receipts(&tool_receipts, None).test_unwrap();
    verify_child_receipts(&[EvidenceChildReceiptRecord {
        seq: 2,
        receipt: child,
    }])
    .test_unwrap();
    assert_eq!(verified.len(), 1);
    assert_eq!(receipt_semantic_summary(&tool_receipts).authorized, 1);
}

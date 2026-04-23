use chio_core_types::canonical::canonical_json_bytes;
use chio_core_types::crypto::{sha256_hex, Keypair};
use chio_core_types::receipt::{
    ChioReceipt, ChioReceiptBody, Decision, ToolCallAction, TrustLevel,
};
use serde_json::json;

fn receipt_body(keypair: &Keypair) -> ChioReceiptBody {
    ChioReceiptBody {
        id: "rcpt-boundary-1".to_string(),
        timestamp: 1_700_000_000,
        capability_id: "cap-boundary-1".to_string(),
        tool_server: "srv-boundary".to_string(),
        tool_name: "echo".to_string(),
        action: ToolCallAction::from_parameters(json!({"b": 2, "a": 1})).unwrap(),
        decision: Decision::Allow,
        content_hash: sha256_hex(b"content"),
        policy_hash: sha256_hex(b"policy"),
        evidence: vec![],
        metadata: None,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: keypair.public_key(),
    }
}

#[test]
fn canonical_json_is_byte_stable_across_object_order() {
    let left = json!({"b": 2, "a": 1, "nested": {"z": true, "m": false}});
    let right = json!({"nested": {"m": false, "z": true}, "a": 1, "b": 2});

    let left_bytes = canonical_json_bytes(&left).unwrap();
    let right_bytes = canonical_json_bytes(&right).unwrap();

    assert_eq!(left_bytes, right_bytes);
}

#[test]
fn receipt_signature_body_excludes_signature_field() {
    let keypair = Keypair::from_seed(&[7; 32]);
    let receipt = ChioReceipt::sign(receipt_body(&keypair), &keypair).unwrap();

    let signed_body_bytes = canonical_json_bytes(&receipt.body()).unwrap();
    let signed_body_text = std::str::from_utf8(&signed_body_bytes).unwrap();

    assert!(!signed_body_text.contains("signature"));
    assert!(receipt.verify_signature().unwrap());
}

#[test]
fn tampering_any_signed_receipt_field_fails_verification() {
    let keypair = Keypair::from_seed(&[8; 32]);
    let receipt = ChioReceipt::sign(receipt_body(&keypair), &keypair).unwrap();

    let mut tampered_tool = receipt.clone();
    tampered_tool.tool_name = "other".to_string();
    assert!(!tampered_tool.verify_signature().unwrap());

    let mut tampered_policy = receipt.clone();
    tampered_policy.policy_hash = sha256_hex(b"other-policy");
    assert!(!tampered_policy.verify_signature().unwrap());

    let mut tampered_decision = receipt.clone();
    tampered_decision.decision = Decision::Deny {
        reason: "tampered".to_string(),
        guard: "test".to_string(),
    };
    assert!(!tampered_decision.verify_signature().unwrap());
}

#[test]
fn json_formatting_does_not_change_receipt_verification() {
    let keypair = Keypair::from_seed(&[9; 32]);
    let receipt = ChioReceipt::sign(receipt_body(&keypair), &keypair).unwrap();

    let pretty = serde_json::to_string_pretty(&receipt).unwrap();
    let compact = serde_json::to_string(&receipt).unwrap();
    let from_pretty: ChioReceipt = serde_json::from_str(&pretty).unwrap();
    let from_compact: ChioReceipt = serde_json::from_str(&compact).unwrap();

    assert!(from_pretty.verify_signature().unwrap());
    assert!(from_compact.verify_signature().unwrap());
    assert_eq!(
        from_pretty.signature.to_hex(),
        from_compact.signature.to_hex()
    );
}

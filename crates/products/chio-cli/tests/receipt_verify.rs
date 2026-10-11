//! Offline worker receipt verification rejects mismatched pins and altered actions.

use std::process::Command;

use chio_core::crypto::Keypair;
use chio_core::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
};

#[test]
fn offline_receipt_verification_requires_every_signature_and_action_hash(
) -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let key = Keypair::generate();
    let body = ChioReceiptBody {
        id: "verification-test".to_string(),
        timestamp: 1_710_000_000,
        capability_id: "process-capability".to_string(),
        tool_server: "reports".to_string(),
        tool_name: "publish".to_string(),
        action: ToolCallAction::from_parameters(serde_json::json!({"report": "original"}))?,
        decision: Some(Decision::Allow),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: "c".repeat(64),
        policy_hash: "d".repeat(64),
        evidence: Vec::new(),
        metadata: None,
        trust_level: Default::default(),
        tenant_id: None,
        kernel_key: key.public_key(),
        bbs_projection_version: None,
    };
    let receipt = ChioReceipt::sign(body.clone(), &key)?;
    let valid = serde_json::to_string(&receipt)?;
    let input = directory.path().join("receipts.ndjson");
    let key_path = directory.path().join("kernel.pub");
    std::fs::write(&key_path, key.public_key().to_hex())?;
    let invoke = || {
        Command::new(env!("CARGO_BIN_EXE_chio"))
            .args(["--json", "receipt", "verify", "--input"])
            .arg(&input)
            .arg("--trusted-kernel-pubkey")
            .arg(&key_path)
            .output()
    };
    std::fs::write(&input, format!("\n{valid}\n{valid}\n"))?;
    let output = invoke()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["receipts_verified"], 2);
    assert_eq!(report["trusted_kernel_key"], key.public_key().to_hex());

    std::fs::write(&key_path, Keypair::generate().public_key().to_hex())?;
    assert!(!invoke()?.status.success());
    std::fs::write(&key_path, key.public_key().to_hex())?;
    let mut tampered = serde_json::to_value(&receipt)?;
    tampered["tool_name"] = serde_json::json!("another_tool");
    let mut bad_hash_body = body;
    bad_hash_body.action.parameter_hash = "0".repeat(64);
    let signed_bad_hash = serde_json::to_string(&ChioReceipt::sign(bad_hash_body, &key)?)?;
    for invalid in [
        String::new(),
        " \n".to_string(),
        "{\"truncated\":".to_string(),
        valid.replacen('{', "{\"tool_name\":\"unsigned-duplicate\",", 1),
        valid.replacen('{', "{\"unsigned_claim\":true,", 1),
        format!("{valid}\n{}\n", serde_json::to_string(&tampered)?),
        signed_bad_hash,
        "x".repeat(8 * 1024 * 1024 + 1),
    ] {
        std::fs::write(&input, invalid)?;
        let output = invoke()?;
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("receipts_verified"));
    }
    Ok(())
}

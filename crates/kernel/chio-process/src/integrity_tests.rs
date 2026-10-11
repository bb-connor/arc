use super::*;
use chio_core_types::crypto::Keypair;
use chio_core_types::receipt::{
    body::{ChioReceipt, ChioReceiptBody},
    decision::{Decision, ToolCallAction},
};

#[test]
fn persisted_thin_unknown_receipts_remain_original_evidence_not_redispatch_authority(
) -> Result<(), Box<dyn std::error::Error>> {
    let key = Keypair::from_seed(&[71; 32]);
    // Historical fixture: this is the thin metadata contract before the repair.
    // Sign once, persist, and exercise only the loaded original evidence below.
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp: 1_710_000_000,
            capability_id: "legacy-capability".into(),
            tool_server: "tools".into(),
            tool_name: "read".into(),
            action: ToolCallAction::from_parameters(json!({}))?,
            decision: Some(Decision::Deny {
                reason: "retained unknown outcome".into(),
                guard: "kernel".into(),
            }),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: sha256_hex(b"null"),
            policy_hash: sha256_hex(b"legacy-policy"),
            evidence: Vec::new(),
            metadata: Some(
                json!({"admission_operation": {"retained_state": "outcome_unknown_after_dispatch"}}),
            ),
            trust_level: Default::default(),
            tenant_id: None,
            kernel_key: key.public_key(),
            bbs_projection_version: None,
        },
        &key,
    )?;
    let original = serde_json::to_vec(&receipt)?;
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("legacy-receipt.json");
    std::fs::write(&path, &original)?;
    let loaded = serde_json::from_slice::<ChioReceipt>(&std::fs::read(&path)?)?;
    assert!(loaded.verify_signature()?);
    let response = ToolCallResponse {
        request_id: "legacy-request".into(),
        verdict: Verdict::Deny,
        output: None,
        reason: Some("retained unknown outcome".into()),
        terminal_state: serde_json::from_value(json!({"state": "completed"}))?,
        receipt: loaded,
        execution_nonce: None,
    };
    assert!(
        !outcome_unknown(&response),
        "thin historical metadata cannot authorize a fresh attempt"
    );
    assert_eq!(serde_json::to_vec(&response.receipt)?, original);
    assert_eq!(std::fs::read(path)?, original);
    assert!(response.receipt.verify_signature()?);
    Ok(())
}

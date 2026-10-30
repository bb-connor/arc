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
    // A receipt carrying only a retained state, without the dispatch binding,
    // is signed once, persisted, and exercised only as loaded evidence.
    let receipt = ChioReceipt::sign(
        ChioReceiptBody {
            id: String::new(),
            timestamp: 1_710_000_000,
            capability_id: "thin-capability".into(),
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
            policy_hash: sha256_hex(b"thin-policy"),
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
    let path = directory.path().join("thin-receipt.json");
    std::fs::write(&path, &original)?;
    let loaded = serde_json::from_slice::<ChioReceipt>(&std::fs::read(&path)?)?;
    assert!(loaded.verify_integrity_embedded_key()?);
    let response = ToolCallResponse {
        request_id: "thin-request".into(),
        verdict: Verdict::Deny,
        output: None,
        reason: Some("retained unknown outcome".into()),
        terminal_state: serde_json::from_value(json!({"state": "completed"}))?,
        receipt: loaded,
        execution_nonce: None,
        denial_code: Some(chio_kernel::ClientDenialCode::KernelUnavailable),
    };
    assert!(
        !outcome_unknown(&response),
        "thin metadata cannot authorize a fresh attempt"
    );
    assert_eq!(serde_json::to_vec(&response.receipt)?, original);
    assert_eq!(std::fs::read(path)?, original);
    assert!(response.receipt.verify_integrity_embedded_key()?);
    Ok(())
}

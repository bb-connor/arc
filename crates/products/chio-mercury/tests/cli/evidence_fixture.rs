//! Shared evidence fixture with an independently selected signer.

use super::*;

pub(super) fn mercury_receipt_with_ts(
    id: &str,
    capability_id: &str,
    timestamp: u64,
    keypair: &Keypair,
) -> ChioReceipt {
    let mercury_metadata = sample_mercury_receipt_metadata();
    let metadata = mercury_metadata
        .into_receipt_metadata_value()
        .expect("mercury metadata value");
    ChioReceipt::sign(
        ChioReceiptBody {
            id: id.to_string(),
            timestamp,
            capability_id: capability_id.to_string(),
            tool_server: "mercury".to_string(),
            tool_name: "release_control".to_string(),
            action: ToolCallAction::from_parameters(serde_json::json!({
                "workflowId": mercury_metadata.business_ids.workflow_id,
                "eventId": mercury_metadata.chronology.event_id,
                "decisionType": mercury_metadata.decision_context.decision_type.as_str(),
                "stage": mercury_metadata.chronology.stage,
                "toolName": "release_control",
            }))
            .expect("action"),
            decision: Some(Decision::Allow),
            receipt_kind: Default::default(),
            boundary_class: Default::default(),
            observation_outcome: None,
            tool_origin: Default::default(),
            redaction_mode: Default::default(),
            actor_chain: Vec::new(),
            content_hash: "content-1".to_string(),
            policy_hash: "policy-1".to_string(),
            evidence: Vec::new(),
            metadata: Some(metadata),
            trust_level: chio_core::receipt::kinds::TrustLevel::default(),
            tenant_id: None,
            kernel_key: keypair.public_key(),
            bbs_projection_version: None,
        },
        keypair,
    )
    .expect("sign mercury receipt")
}

pub(super) fn export_fixture_package(receipt_db_path: &Path, output_dir: &Path) {
    evidence_export::cmd_evidence_export(
        output_dir,
        None,
        None,
        None,
        None,
        None,
        true,
        None,
        None,
        false,
        Some(receipt_db_path),
        None,
        None,
        &Keypair::from_seed(&[58; 32]),
    )
    .expect("export evidence fixture package");
}

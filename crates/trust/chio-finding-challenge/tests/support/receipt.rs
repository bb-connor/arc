use super::*;

/// Parameters of `signed_receipt_for_server`.
pub(super) struct ServerReceiptSpec<'a> {
    pub(super) timestamp: u64,
    pub(super) tool_server: &'a str,
    pub(super) tool_name: &'a str,
    pub(super) action: ToolCallAction,
    pub(super) decision: Decision,
    pub(super) content_hash: &'a str,
    pub(super) metadata: Option<serde_json::Value>,
}

pub(super) fn signed_receipt_for_server(
    kernel: &Keypair,
    params: ServerReceiptSpec<'_>,
) -> Built<ChioReceipt> {
    let ServerReceiptSpec {
        timestamp,
        tool_server,
        tool_name,
        action,
        decision,
        content_hash,
        metadata,
    } = params;
    let body = ChioReceiptBody {
        id: String::new(),
        timestamp,
        capability_id: format!("cap-{timestamp}"),
        tool_server: tool_server.to_string(),
        tool_name: tool_name.to_string(),
        action,
        decision: Some(decision),
        receipt_kind: Default::default(),
        boundary_class: Default::default(),
        observation_outcome: None,
        tool_origin: Default::default(),
        redaction_mode: Default::default(),
        actor_chain: Vec::new(),
        content_hash: content_hash.to_string(),
        policy_hash: "policy-finding-market".to_string(),
        evidence: Vec::new(),
        metadata,
        trust_level: TrustLevel::Mediated,
        tenant_id: None,
        kernel_key: kernel.public_key(),
        bbs_projection_version: None,
    };
    Ok(ChioReceipt::sign(body, kernel)?)
}
